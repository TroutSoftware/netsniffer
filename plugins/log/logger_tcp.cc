
// Snort includes
#include <framework/decode_data.h>
#include <framework/inspector.h>
#include <framework/module.h>

// System includes
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <thread>

// Local includes
#include "lioli.h"
#include "log_framework.h"
#include "logger_tcp.h"

// Debug includes

namespace logger_tcp {
namespace {

const char *s_name = "logger_tcp";
const char *s_help = "Outputs LioLi trees over a tcp connection";

const snort::Parameter module_params[] = {
    {"alias", snort::Parameter::PT_STRING, nullptr, nullptr,
     "The alias name for the logger with specific config"},
    {"output_ip", snort::Parameter::PT_IP4, nullptr, nullptr,
     "The ip address data should be written to"},
    {"output_port", snort::Parameter::PT_PORT, nullptr, nullptr,
     "The port number data should be written to"},
    {"output_ip_env", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Name of an environment variable containing the ip address data should be "
     "written to"},
    {"output_port_env", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Name of an environment variable containing the port number data should "
     "be written to"},
    {"queue_max", snort::Parameter::PT_INT, "1:10000", "1024",
     "Max number of trees that will be queued before discarding"},
    {"restart_interval_s", snort::Parameter::PT_INT, "0:86400", "0",
     "Seconds between restarting the serializer (max: 86400 s (1 day), 0 = "
     "never)), a restart will result in a new connection being made to the "
     "server"},
    {"serializer", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Serializer to use for generating output"},
    {"retry_interval_ms", snort::Parameter::PT_INT, "10:10000", "100",
     "ms between retries after a log output tcp connection has been rejected "
     "or closed by the receiving side"},

    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

const PegInfo s_pegs[] = {
    {CountType::SUM, "logs_in", "Count of logs we were asked to write"},
    {CountType::SUM, "logs_out", "Count of logs we sent on the connection"},
    {CountType::SUM, "overflows", "Count of logs we discarded due to overflow"},
    {CountType::MAX, "max_queued",
     "Max number of items ever queued at one time"},
    {CountType::SUM, "write_errors", "Count of write errors detected"},
    {CountType::SUM, "restarts", "Count of (re)starts of the serializer"},
    {CountType::SUM, "epoll_err", "Number of errors from epoll"},
    {CountType::SUM, "would_block",
     "Number of time we couldn't write to a socket that we were told was "
     "writable"},
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
  PegCount epoll_err = 0;
  PegCount would_block = 0;
} s_peg_counts;

// Compile time sanity check of number of entries in s_pegs and s_peg_counts
static_assert(
    (sizeof(s_pegs) / sizeof(PegInfo)) - 1 ==
        sizeof(PegCounts) / sizeof(PegCount),
    "Entries in s_pegs doesn't match number of entries in s_peg_counts");

// MAIN object of this file
class Logger : public LioLi::Logger {
  using clock = std::chrono::steady_clock;

  std::mutex mutex; // Protects members

  // Configs
  std::string serializer_name;
  uint16_t port;
  uint32_t ipv4;
  uint32_t max_queue_size = 1;
  uint32_t serializer_restart_interval_s = 0; // 0 = never
  uint64_t dropped_sequence_count =
      0; // Counts the number of packages dropped in this sequence
  uint32_t retry_interval_ms = 100;

  std::deque<LioLi::Tree> queue;

  // Worker thread controls
  std::thread worker_thread;
  std::condition_variable cv; // Used to enable worker to sleep when there
                              // aren't anything for it to do
  bool terminate = false;     // Set to true if worker loop should be terminated
  bool worker_done = false;   // Worker won't block anymore
  bool data_loss = false;     // Set to true when we might have lost data

  class Socket {
    // NOTE: Calling functions in this class has a lot of sideeffects, use with
    // caution
    uint32_t ipv4;
    uint16_t port;

    int epfd = epoll_create1(EPOLL_CLOEXEC); // epoll socket
    int osocket = -1;                        // Socket used for communication
    std::string output_string; // What we are currently trying to write
    ssize_t output_index = 0; // Place in output_string that we are writing from
    std::string my_name;

    bool add_socket_to_epoll() {
      // Create epool struct corresponding to this socket
      epoll_event ev;

      ev.events = EPOLLOUT;
      ev.data.fd = osocket;

      if (::epoll_ctl(epfd, EPOLL_CTL_ADD, osocket, &ev)) {
        snort::ParseError("TCP Logger connection error (Could not add socket "
                          "to epoll for: %s reason: %s)\n",
                          my_name.c_str(), std::strerror(errno));
        return false;
      }
      return true;
    }

    bool remove_socket_from_epoll() {
      // Create epool struct corresponding to this socket
      epoll_event ev;

      ev.events = EPOLLOUT;
      ev.data.fd = osocket;

      if (::epoll_ctl(epfd, EPOLL_CTL_DEL, osocket, &ev)) {
        snort::ParseError("TCP Logger connection error (Could not remove "
                          "socket from epoll for: %s reason: %s)\n",
                          my_name.c_str(), std::strerror(errno));
        return false;
      }
      return true;
    }

    void close_socket() {

      if (-1 != osocket) {
        remove_socket_from_epoll(); // Just to be nice, the ::close should also
                                    // to this
        ::close(osocket);
      }

      osocket = -1;

      // We never split an output over multiple connections
      output_string.clear();
      output_index = 0;
    }

  public:
    Socket(uint32_t ipv4, uint16_t port, std::string my_name)
        : ipv4(ipv4), port(port), my_name(my_name) {
      assert(-1 != epfd);
    }

    ~Socket() {
      close_socket();
      ::close(epfd);
    }

    bool connect() {
      close_socket(); // Make sure we are in a known state

      osocket = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

      sockaddr_in addr;
      addr.sin_family = AF_INET;
      addr.sin_port = htons(port);
      addr.sin_addr.s_addr = ipv4;

      if (::connect(osocket, (sockaddr *)&addr, sizeof(addr)) &&
          errno != EAGAIN && errno != EINPROGRESS) {
        snort::ParseError("TCP Logger connection error (Could not create "
                          "connecting socket for: %s reason: %s)\n",
                          my_name.c_str(), std::strerror(errno));
        close_socket();
        return false;
      }

      add_socket_to_epoll();

      return true;
    }

    operator bool() const { return (-1 != osocket); }

    // Returns -1 on fatal error, 0 on restart loop, 1 if socket writeable
    int epoll_wait(uint32_t retry_interval_ms) {
      // Wait for something to happen with the socket
      epoll_event wait_ev;
      int epwret = ::epoll_wait(epfd, &wait_ev, 1, 1000 /* max ms to wait */);

      if (0 == epwret) {
        return 0;
      } else if (-1 == epwret) {
        snort::ParseError("TCP Logger connection error (Epoll wait returned "
                          "with error for: %s reason: %s)\n",
                          my_name.c_str(), std::strerror(errno));

        return -1;
      }

      assert(1 == epwret); // if anything excpet 1 is seen at this point we have
                           // a programming or fatal error

      if (wait_ev.events & (EPOLLHUP | EPOLLERR)) {
        if (wait_ev.events & EPOLLERR) {
          std::scoped_lock lock(peg_count_mutex);
          s_peg_counts.epoll_err++;
        }
        close_socket();
        std::this_thread::sleep_for(
            std::chrono::milliseconds(retry_interval_ms));
        return 0;
      }

      assert(wait_ev.events & EPOLLOUT); // If this fires, there is some
                                         // condition we aren't handling

      return 1;
    }

    void queue(std::string &&input) {
      assert(output_string.empty());
      output_string = input;
    }

    // Returns true if flush was complete, false if loop should be restarted
    // NOTE: Flush is only for our internal stuff, it's not a connection flush
    bool flush(bool has_more) {
      // Output what we are waiting to output
      if (static_cast<ssize_t>(output_string.length()) > output_index) {
        ssize_t remaining = output_string.length() - output_index;
        ssize_t bytes = ::send(osocket, output_string.data() + output_index,
                               remaining, (has_more) ? 0 : MSG_MORE);

        if (bytes >= 0) {
          assert(remaining <= bytes);

          // All was not sent
          if (remaining > bytes) {
            output_index += bytes;
            return false;
          }

          // All was sent
          output_string.clear();
          output_index = 0;
          return true;
        } else {                                // Some error
          static_assert(EAGAIN == EWOULDBLOCK); // Holds true on Linux, fix if
                                                // new platform is introduced
          if (errno == EWOULDBLOCK) {
            std::scoped_lock lock(peg_count_mutex);
            s_peg_counts.would_block++;
          } else {
            close_socket();
          }
          return false;
        }
      }
      return true;
    }
  };

  void worker_loop() {
    std::shared_ptr<LioLi::Serializer> serializer;

    // Don't do anything until we have our serializer
    while (!terminate) {
      serializer = LioLi::LogDB::get<LioLi::Serializer>(serializer_name);

      if (serializer != serializer->get_null_obj())
        break;

      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::chrono::time_point<clock>
        next_timeout; // Keeps track of when we should restart serializer
                      // context
    std::shared_ptr<LioLi::Serializer::Context> context;
    Socket socket(ipv4, port, get_name());

    // Main loop
    while (!terminate) {
      if (!socket) {
        socket.connect();

        // This might set the data_loss too frequently, but it's only a help,
        // not a promise
        std::scoped_lock lock(mutex);
        data_loss = true;
      }

      // Wait for something to happen with the socket
      switch (socket.epoll_wait(retry_interval_ms)) {
      case 0:
        continue; // socket is not ready/might need to be recreated
      case -1:
        goto while_end; // unhandled error, exit loop
      default:
        break; // socket is ready for writing
      }

      // Flush what we have stored
      bool has_more;
      {
        std::scoped_lock lock(mutex);
        has_more = !queue.empty();
      }

      if (!socket.flush(has_more)) {
        continue; // Couldn't write what was stored, socket might be closed
      }

      // Ensure we have a valid context
      if (next_timeout <= clock::now() || !context) {
        if (context) {
          socket.queue(context->close());
          context.reset();
          continue; // Will eventually reach the flush
        }

        context = serializer->create_context();
        if (serializer_restart_interval_s != 0) {
          next_timeout = clock::now() +
                         std::chrono::seconds(serializer_restart_interval_s);
        } else {
          next_timeout = std::chrono::time_point<clock>::max();
        }

        std::scoped_lock lock(peg_count_mutex);
        s_peg_counts.restarts++;
      }

      std::unique_lock lock(mutex);

      if (!queue.empty()) {
        if (dropped_sequence_count != 0) {
          snort::WarningMessage(
              "WARNING: %s droped %lu tree(s) from queue, resuming output\n",
              get_name(), dropped_sequence_count);
          dropped_sequence_count = 0;
        }
        socket.queue(context->serialize(std::move(queue.front())));
        queue.pop_front();
        continue; // Will eventually send
      }

      cv.wait_until(lock, next_timeout,
                    [this] { return terminate || !queue.empty(); });
    }
  while_end:

  {
    std::unique_lock lock(mutex);
    worker_done = true;
  }
    cv.notify_all();
  }

public:
  Logger(const char *name) : LioLi::Logger(name) {}

  ~Logger() {
    stop(); // Stops worker thread
  }

  bool had_data_loss(bool clear_flag) override {
    std::scoped_lock lock(mutex);
    bool old_value = data_loss;

    data_loss &= !clear_flag;

    return old_value;
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
        data_loss = true;
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

  void set_port(uint16_t port) { this->port = port; }

  void set_ipv4(uint32_t ip) { ipv4 = ip; }

  void set_retry_interval(uint32_t retry_interval) {
    retry_interval_ms = retry_interval;
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
        cv.wait_for(lock, std::chrono::seconds(2),
                    [this] { return worker_done; });

        if (!worker_done) {
          // Still not done, set it free
          worker_thread.detach();
          return;
        }
      }
      worker_thread.join();
    }
  }
};

class Module : public snort::Module {
  Module() : snort::Module(s_name, s_help, module_params) {}

  ~Module() {}

  struct ConfigColector {
    std::string name;
    uint32_t ipv4 = 0;
    uint16_t port = 0;
    uint32_t queue_limit;
    uint32_t restart_interval;
    uint32_t retry_interval;
    std::string serializer;
  };

  std::stack<ConfigColector> config_stack;

  bool begin(const char *, int, snort::SnortConfig *) override {
    // Make new element
    config_stack.emplace();
    return true;
  }

  bool end(const char *, int, snort::SnortConfig *) override {
    assert(!config_stack.empty());

    // Check validity
    if (config_stack.top().name.empty()) {
      if (config_stack.size() > 1) {
        snort::ErrorMessage("ERROR: No alias given for entry\n");
        config_stack.pop();
        return false;
      }

      config_stack.top().name = s_name;
    }

    if (config_stack.top().serializer.empty()) {
      snort::ErrorMessage("ERROR: No serializer given for entry\n");
      config_stack.pop();
      return false;
    }

    if (config_stack.top().ipv4 == 0) {
      snort::ErrorMessage("ERROR: No ip address given\n");
      config_stack.pop();
      return false;
    }

    if (config_stack.top().port == 0) {
      snort::ErrorMessage("ERROR: No valid port given\n");
      config_stack.pop();
      return false;
    }

    // Create entry in DB
    if (!LioLi::LogDB::register_type<Logger>(config_stack.top().name.c_str())) {
      snort::ErrorMessage("ERROR: Found duplicate name/alias '%s'\n",
                          config_stack.top().name.c_str());
      config_stack.pop();
      return false;
    }

    auto logger = LioLi::LogDB::get<Logger>(config_stack.top().name.c_str());

    if (!logger) {
      snort::ErrorMessage("ERROR: Unable to initialize logger\n");
      config_stack.pop();
      return false;
    }

    // Initialize specific logger
    logger->set_serializer(config_stack.top().serializer.c_str());
    logger->set_max_queue_size(config_stack.top().queue_limit);
    logger->set_serializer_restart_interval_s(
        config_stack.top().restart_interval);
    logger->set_port(config_stack.top().port);
    logger->set_ipv4(config_stack.top().ipv4);
    logger->set_retry_interval(config_stack.top().retry_interval);

    // Start the logger
    logger->start();

    config_stack.pop();
    return true;
  }

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    assert(!config_stack.empty());

    // TODO: Implement the _env versions
    if (val.is("alias")) {
      std::string alias = val.get_as_string();

      if (alias.empty()) {
        snort::ErrorMessage("ERROR: Alias specified with empty name\n");
        return false;
      }

      config_stack.top().name = alias;

    } else if (val.is("output_ip")) {
      config_stack.top().ipv4 = val.get_ip4();
      /*    } else if (val.is("output_ip_env")) {
            std::string env_name = val.get_as_string();
            const char *name = std::getenv(env_name.c_str());

            if (name && *name) {
              ...
          }*/
    } else if (val.is("output_port")) {
      config_stack.top().port = val.get_uint16();
      /*    } else if (val.is("output_port_env")) {
            std::string env_name = val.get_as_string();
            const char *name = std::getenv(env_name.c_str());

            if (name && *name) {
              ...
          }*/
    } else if (val.is("queue_max")) {
      config_stack.top().queue_limit = val.get_uint32();
    } else if (val.is("restart_interval_s")) {
      config_stack.top().restart_interval = val.get_uint32();
    } else if (val.is("retry_interval_ms")) {
      config_stack.top().retry_interval = val.get_uint32();
    } else if (val.is("serializer")) {
      std::string serializer = val.get_as_string();

      if (serializer.empty()) {
        snort::ErrorMessage("ERROR: empty name given for serializer\n");
        return false;
      }

      config_stack.top().serializer = serializer;
    } else {
      snort::ErrorMessage("ERROR: Parameter '%s' is not implemented\n",
                          val.get_name());
      return false;
    }

    return true;
  }

  Usage get_usage() const override {
    return GLOBAL;
  } // TODO(mkr): Figure out what the usage type means

  const PegInfo *get_pegs() const override { return s_pegs; }

  PegCount *get_counts() const override {
    // TODO: This will mess when snort tries to clear the pegs, find a solution
    // that lets this work in a multithreaded environment
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

} // namespace logger_tcp
