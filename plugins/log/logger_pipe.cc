
// Snort includes
#include <framework/decode_data.h>
#include <framework/inspector.h>
#include <framework/module.h>

// System includes
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <deque>
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>

// Local includes
#include "lioli.h"
#include "log_framework.h"
#include "logger_pipe.h"

// Debug includes

namespace logger_pipe {
namespace {

static const char *s_name = "logger_pipe";
static const char *s_help = "Outputs LioLi trees to a named pipe";

static const snort::Parameter module_params[] = {
    {"pipe_name", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Pipe name logs should be written to"},
    {"pipe_env", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Pipe name will be read from environment variable"},
    {"queue_max", snort::Parameter::PT_INT, "1:10000", "1024",
     "Max number of trees that will be queued before discarding"},
    {"restart_interval_s", snort::Parameter::PT_INT, "0:86400", "0",
     "Time between restarting the serializer (max: 86400 s (1 day), 0 = "
     "never))"},
    {"serializer", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Serializer to use for generating output"},

    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

const PegInfo s_pegs[] = {
    {CountType::SUM, "logs_in", "Count of logs we were asked to write"},
    {CountType::SUM, "logs_out", "Count of logs we sent on the pipe"},
    {CountType::SUM, "overflows", "Count of logs we discarded due to overflow"},
    {CountType::MAX, "max_queued",
     "Max number of items ever queued at one time"},
    {CountType::SUM, "write_errors", "Count of write errors detected"},
    {CountType::SUM, "restarts", "Count of (re)starts of the serializer"},
    {CountType::END, nullptr, nullptr}};

// This must match the s_pegs[] array
// NOTE: we cant use the THREAD_LOCAL pattern here as we have our own threads
std::mutex peg_count_mutex; // Protects the peg counts
struct PegCounts {
  PegCount logs_in = 0;
  PegCount logs_out = 0;
  PegCount overflows = 0;
  PegCount max_queued = 0;
  PegCount write_errors = 0;
  PegCount restarts = 0;
} s_peg_counts;

// Compile time sanity check of number of entries in s_pegs and s_peg_counts
static_assert(
    (sizeof(s_pegs) / sizeof(PegInfo)) - 1 ==
        sizeof(PegCounts) / sizeof(PegCount),
    "Entries in s_pegs doesn't match number of entries in s_peg_counts");

// SIGPIPE handler
void pipe_signal_handler(int) {}

// MAIN object of this file
class Logger : public LioLi::Logger {
  using clock = std::chrono::steady_clock;

  std::mutex mutex; // Protects members

  // Configs
  std::string serializer_name;
  std::string pipe_name;
  uint32_t max_queue_size = 1;
  uint32_t serializer_restart_interval_s = 0; // 0 = never
  uint64_t dropped_sequence_count =
      0; // Counts the number of packages dropped in this sequence

  std::deque<LioLi::Tree> queue;

  // Worker thread controls
  std::thread worker_thread;
  std::condition_variable cv; // Used to enable worker to sleep when there
                              // aren't anything for it to do
  bool terminate = false;     // Set to true if worker loop should be terminated
  bool worker_done = false;   // Worker won't block anymore

  std::ofstream open_pipe(std::unique_lock<std::mutex> &lock) {
    assert(serializer_name.length() != 0 && pipe_name.length() != 0);

    if (terminate)
      return std::ofstream();

    std::ios_base::openmode openmode = std::ios::out;

    if (LioLi::LogDB::get<LioLi::Serializer>(serializer_name)->is_binary()) {
      openmode |= std::ios::binary;
    }

    std::string tmp_name = pipe_name;

    // Release the lock while opening, as it will block until a reader is
    // attached to the pipe
    lock.unlock();
    std::ofstream pipe = std::ofstream(tmp_name, openmode);
    lock.lock();

    if (!pipe.good() || !pipe.is_open()) {
      snort::ParseAbort(
          "ERROR: Could not open output pipe: %s with reason %s\n",
          pipe_name.c_str(), std::strerror(errno));

      // This is considered a non-recoverable error, e.g. pipe doesn't exists
      terminate = true;
    }

    return pipe;
  }

  void worker_loop() {
    // Stay protected
    std::unique_lock lock(mutex);

    // Keeps track of when we should restart serializer context
    std::chrono::time_point<clock> next_timeout;

    // Our serializer
    auto serializer = LioLi::LogDB::get<LioLi::Serializer>(serializer_name);

    while (serializer == serializer->get_null_obj()) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
      serializer = LioLi::LogDB::get<LioLi::Serializer>(serializer_name);
    }

    std::shared_ptr<LioLi::Serializer::Context> context;

    std::ofstream pipe;

    while (!terminate) {
      if (!pipe.is_open()) {
        // open_pipe will set terminate to true if something went wrong
        pipe = open_pipe(lock);
        // We always start a new pipe with a fresh context
        context.reset();
        continue;
      }

      if (next_timeout <= clock::now() || !context) {
        if (context) {
          lock.unlock();
          pipe << context->close();
          pipe.flush();
          lock.lock();

          if (!pipe.good()) {
            snort::LogMessage("LOG: %s unable to write end to pipe, retrying\n",
                              s_name);
            pipe.close();
            {
              std::scoped_lock lock(peg_count_mutex);
              s_peg_counts.write_errors++;
            }

            continue;
          }
        }

        context = serializer->create_context();
        if (serializer_restart_interval_s != 0) {
          next_timeout = clock::now() +
                         std::chrono::seconds(serializer_restart_interval_s);
        } else {
          next_timeout = std::chrono::time_point<clock>::max();
        }

        {
          std::scoped_lock lock(peg_count_mutex);
          s_peg_counts.restarts++;
        }
      }

      if (!queue.empty()) {
        if (dropped_sequence_count != 0) {
          snort::WarningMessage(
              "WARNING: %s droped %lu tree(s) from queue, resuming output\n",
              s_name, dropped_sequence_count);
          dropped_sequence_count = 0;
        }
        auto output = context->serialize(std::move(queue.front()));
        queue.pop_front();

        // We can't write while being locked, as the write might block
        lock.unlock();
        pipe << output;
        lock.lock();

        if (!pipe.good()) {
          snort::LogMessage(
              "LOG: %s unable to write tree to pipe, skipping and retrying\n",
              s_name);
          pipe.close();
          {
            std::scoped_lock lock(peg_count_mutex);
            s_peg_counts.write_errors++;
          }
          continue;
        } else {
          std::scoped_lock lock(peg_count_mutex);
          s_peg_counts.logs_out++;
        }
      }

      if (!terminate && queue.empty()) {
        cv.wait_until(lock, next_timeout);
      }
    }

    if (pipe.good() && pipe.is_open() && context) {
      lock.unlock();
      pipe << context->close();
      lock.lock();
      pipe.close();
    }

    worker_done = true;
    lock.unlock();
    cv.notify_all();
  }

public:
  Logger(const char *name) : LioLi::Logger(name) {
    // A SIGPIPE will fire if we are trying to write to a pipe without a reader,
    // to avoid termination of snort we must handle the signal
    static std::once_flag oflag;
    std::call_once(oflag, []() { std::signal(SIGPIPE, pipe_signal_handler); });
  }

  ~Logger() {}

  bool is_valid() {
    bool all_valid = true; // Assume all good

    if (pipe_name.empty()) {
      snort::ErrorMessage("ERROR: no pipe_name specified for %s\n", get_name());
      all_valid = false;
    }
    if (serializer_name.empty()) {
      snort::ErrorMessage("ERROR: no serializer specified for %s\n",
                          get_name());
      all_valid = false;
    }

    return all_valid;
  }

  void operator<<(const LioLi::Tree &&tree) override {
    {
      std::scoped_lock lock(mutex);

      assert(max_queue_size > 0);

      // Reduce size of the queue until there is space for the new element
      while (queue.size() > max_queue_size - 1) {
        if (dropped_sequence_count++ == 0) {
          snort::WarningMessage("WARNING: %s dropping tree(s) from queue\n",
                                s_name);
        }
        queue.pop_front();
        {
          std::scoped_lock lock(peg_count_mutex);
          s_peg_counts.overflows++;
        }
      }

      queue.push_back(std::move(tree));

      {
        std::scoped_lock lock(peg_count_mutex);
        if (s_peg_counts.max_queued < queue.size()) {
          s_peg_counts.max_queued = queue.size();
        }

        s_peg_counts.logs_in++;
      }
    }

    // Kick worker
    cv.notify_all();
  }

  void set_serializer(const char *name) {
    std::scoped_lock lock(mutex);

    assert(serializer_name.empty() ||
           name == serializer_name); // We do not handle changing of the
                                     // serializer name

    serializer_name = name;
  }

  const std::string &get_serializer() { return serializer_name; }

  void set_pipe_name(std::string name) {
    std::scoped_lock lock(mutex);

    assert(pipe_name.empty() ||
           name == pipe_name); // We do not handle changing of the pipe name

    pipe_name = name;
  }

  const std::string &get_pipe_name() { return pipe_name; }

  void set_max_queue_size(uint32_t max) {
    std::scoped_lock lock(mutex);

    assert(max > 0); // We need to be able to queue at least one element

    // If queue size is being reduced, reduce it
    if (queue.size() > max) {
      snort::WarningMessage(
          "WARNING: %s dropping %li trees from queue due to resize\n", s_name,
          queue.size() - max);
    }
    while (queue.size() > max) {
      queue.pop_front();
    }

    max_queue_size = max;
  }

  void set_serializer_restart_interval_s(uint32_t interval) {
    {
      std::scoped_lock lock(mutex);

      serializer_restart_interval_s = interval;
    }
    // Kick worker
    cv.notify_all();
  }

  // Call after all configuration is done
  void start() {
    terminate = false;
    worker_done = false;
    worker_thread = std::thread{&Logger::worker_loop, this};
  }

  // Call to terminate
  void stop() {
    // Check worker is running
    if (worker_thread.joinable()) {
      std::unique_lock lock(mutex);

      // If thread hasn't killed it self
      if (!worker_done) {
        terminate = true;

        // Kick worker, we do not release the lock, as we need to reach
        // wait_for(..) before the worker is allowed to continue
        cv.notify_all();

        // Give worker a chance to go down gracefully
        if (std::cv_status::timeout ==
                cv.wait_for(lock, std::chrono::seconds(2)) &&
            !worker_done) {
          // Faking a reader (most likely it is stuck in the open)
          std::ifstream pipe = std::ifstream(pipe_name, std::ios::in);
          cv.wait_for(lock, std::chrono::seconds(2));
          if (!worker_done) {
            // Still not done, set it free
            worker_thread.detach();
            return;
          }
        }
      }
      worker_thread.join();
    }
  }
};

class Module : public snort::Module {
  Module() : snort::Module(s_name, s_help, module_params) {
    LioLi::LogDB::register_type<Logger>(s_name);
  }

  ~Module() {
    // Stop worker
    LioLi::LogDB::get<Logger>(s_name)->stop();
  }

  bool begin(const char *, int, snort::SnortConfig *) override { return true; }

  bool end(const char *, int, snort::SnortConfig *) override {
    auto logger = LioLi::LogDB::get<Logger>(s_name);
    if (logger->is_valid()) {
      // Start worker
      logger->start();
      return true;
    }

    return false;
  }

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    auto logger = LioLi::LogDB::get<Logger>(s_name);
    if (val.is("pipe_name") && val.get_as_string().size() > 0) {

      if (!logger->get_pipe_name().empty()) {
        snort::ErrorMessage("ERROR: You can only set name/env once in %s\n",
                            s_name);
        return false;
      }

      LioLi::LogDB::get<Logger>(s_name)->set_pipe_name(val.get_string());

      return true;
    } else if (val.is("pipe_env")) {
      std::string env_name = val.get_as_string();
      const char *name = std::getenv(env_name.c_str());

      if (name && *name) {
        if (!logger->get_pipe_name().empty()) {
          snort::ErrorMessage("ERROR: You can only set name/env once in %s\n",
                              get_name());
          return false;
        }

        logger->set_pipe_name(name);

        return true;
      }

      snort::ErrorMessage(
          "ERROR: Could not read log pipe name from environment: %s in %s\n",
          env_name.c_str(), get_name());
    } else if (val.is("serializer") && val.get_as_string().size() > 0) {

      if (!logger->get_serializer().empty()) {
        snort::ErrorMessage("ERROR: You can only set serializer once in %s\n",
                            get_name());
        return false;
      }

      logger->set_serializer(val.get_string());

      return true;
    } else if (val.is("queue_max")) {
      // We can't do duplication check for queue_max as it has a default value
      // (which will be set before an explicit value)

      logger->set_max_queue_size(val.get_uint32());
      return true;
    } else if (val.is("restart_interval_s")) {
      logger->set_serializer_restart_interval_s(val.get_uint32());
      return true;
    }

    // fail if we didn't get something valid
    return false;
  }

  Usage get_usage() const override {
    return GLOBAL;
  } // TODO(mkr): Figure out what the usage type means

  const PegInfo *get_pegs() const override { return s_pegs; }

  PegCount *get_counts() const override {
    // TODO: This will mess when snort tries to clear the pegs, find a solution
    // that
    //       lets this work in a multithreaded environment
    // We need to return a copy of the peg counts as we don't know when snort
    // are done with them
    static PegCounts static_pegs;

    std::scoped_lock lock(peg_count_mutex);
    static_pegs = s_peg_counts;

    return reinterpret_cast<PegCount *>(&static_pegs);
  }

public:
  static snort::Module *ctor() { return new Module(); }
  static void dtor(snort::Module *p) { delete p; }
};

class Inspector : public snort::Inspector {
  void eval(snort::Packet *) override {};

public:
  static snort::Inspector *ctor(snort::Module *) { return new Inspector(); }
  static void dtor(snort::Inspector *p) { delete p; }
};

} // namespace

const snort::InspectApi inspect_api = {
    {
        PT_INSPECTOR,
        sizeof(snort::InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        Module::ctor,
        Module::dtor,
    },

    snort::IT_PASSIVE,
    PROTO_BIT__NONE,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    Inspector::ctor,
    Inspector::dtor,
    nullptr, // ssn
    nullptr  // reset
};

} // namespace logger_pipe
