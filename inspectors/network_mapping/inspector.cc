#include <chrono>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

#include "framework/inspector.h"
#include "framework/module.h"
#include "protocols/packet.h"
#include "pub_sub/appid_event_ids.h"
#include "pub_sub/http_event_ids.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "sfip/sf_ip.h"

using namespace snort;



static const Parameter nm_params[] = {
  {"cache_size", Parameter::PT_INT, "0:max32", "0", "set cache size"},
  {"log_file", Parameter::PT_STRING, nullptr, "flow.txt",
   "set output file name"},

  {nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr}
};

// MKR: This class is untested and WIP, don't use it.
class LogFile {
  enum class State {
    initial,    // Initial state
    open,       // File is open and ready for use
    full,       // The current file is full
    aborted     // We have stopped writing to an actual file
  } state = State::initial;

  std::mutex      mutex;
  std::ofstream   stream;                 // Stream logs are written to
  std::string     base_file_name;         // The base filename, i.e. without the timestamp extension
  unsigned        log_files_opened = 0;   // Count of logfiles that has been opened
  unsigned        log_lines_total = 0;    // Total number of log lines written (sum of lines written to all files)
  unsigned        log_lines_written = 0;  // Number of log lines written in the current file
  const unsigned  max_lines_pr_file = 1000000;  // When this number of lines has been written a new file will be written

  // Flush parameters
  const unsigned  lines_beween_flushes = 100; // Number of lines between flushes
  unsigned        lines_since_last_flush = 0; // Number of lines since last flush

  // TODO(mkr) make a flush based on time too

public:
  void set_file_name(char *new_name) {
    std::scoped_lock guard(mutex);

    assert(State::initial == state);    // We can't set the filename after we have started to use the name
    assert(new_name);                   // Make sure we got some input

    base_file_name = new_name;
  }

  void logstream(std::string message) noexcept {
    std::scoped_lock guard(mutex);

    switch (state) {
      case State::aborted:
        return;

      case State::full:
        stream.close();
        lines_since_last_flush = 0;

        [[fallthrough]]

      case State::initial: {
          using namespace std::chrono;
          assert(!base_file_name.empty());  // Logic error if the filename isn't set at this point

          // Choosing the clock is not trivial, using system_clock for now... need to be re-evaluated
          // Best would be utc_clock, but it isn't supported by our compiler version
          // steady_clock can repeat the same time between boots, even it is always increasing in the same runb
          // system_clock is not ideal, as it can be adjusted and hence repeat...
          const auto cur_time = system_clock::now().time_since_epoch();
          uint64_t cur_time_ms = duration_cast<milliseconds>(cur_time).count();

          std::string file_name(base_file_name);
          file_name += cur_time_ms;

          // TODO(mkr) make sure the right parameters are used e.g. append/truncate if file exists
          stream.open(file_name);

          if(!stream.is_open()) {
            state = State::aborted;
            return;
          }

          state = State::open;
          log_files_opened++;
          log_lines_written = 0;
        }

        [[fallthrough]]

      case State::open:

        // TODO(mkr) Investigate how failures to write manifest them self and handle them gracefully
        stream << message << std::endl;

        log_lines_total++;
        log_lines_written++;
        lines_since_last_flush++;

        if (max_lines_pr_file >= log_lines_written)
          state = State::full;

        if (lines_beween_flushes >= lines_since_last_flush) {
          stream.flush();
          lines_since_last_flush = 0;
        }
    }
  }
};

class NetworkMappingModule : public Module {
public:
enum class file_error { success, uninitialized_file, cannot_write };
  NetworkMappingModule()
      : Module("network_mapping",
               "Help map resources in the network based on their comms",
               nm_params),
        logfile(), logfile_mx() {}
  std::ofstream logfile;
  std::mutex logfile_mx;

  Usage get_usage() const override { return CONTEXT; }

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("log_file") && val.get_string()) {
      logfile.open(val.get_string());
    }

    return true;
  }

  file_error logstream(std::string message) noexcept {
    std::lock_guard<std::mutex> guard(logfile_mx);
    if (!logfile.is_open()) {
      return file_error::uninitialized_file;
    }
    logfile << message << std::endl;
    return file_error::success;
  }
};

class NetworkMappingInspector : public snort::Inspector {
public:
  NetworkMappingInspector(NetworkMappingModule *module) : module(*module) {}
  NetworkMappingModule &module;


  void eval(snort::Packet *packet) override {
    if (packet) {
        if(packet->has_ip()) {
            char ip_str[INET_ADDRSTRLEN];
            std::stringstream ss;

            sfip_ntop(packet->ptrs.ip_api.get_src(), ip_str, sizeof(ip_str));
            ss << ip_str << ':' << packet->ptrs.sp << " -> ";

            sfip_ntop(packet->ptrs.ip_api.get_dst(), ip_str, sizeof(ip_str));
            ss << ip_str << ':' << packet->ptrs.dp;

            module.logstream(ss.str());
        }
    }
  }

  class EventHandler : public snort::DataHandler {
  public:
    EventHandler(NetworkMappingModule &module)
        : DataHandler("network_mapping"), module(module) {}
    NetworkMappingModule &module;

    void handle(snort::DataEvent &, snort::Flow *flow) override {
      if (flow && flow->service) {
        module.logstream(std::string(flow->service));
      }
    }
  };

  bool configure(SnortConfig *) override {
    DataBus::subscribe_network(intrinsic_pub_key,
                               IntrinsicEventIds::FLOW_SERVICE_CHANGE,
                               new EventHandler(module));
    DataBus::subscribe_network(intrinsic_pub_key,
                               IntrinsicEventIds::FLOW_STATE_RELOADED,
                               new EventHandler(module));
    DataBus::subscribe_network(intrinsic_pub_key,
                               IntrinsicEventIds::AUXILIARY_IP,
                               new EventHandler(module));
    /* DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::PKT_WITHOUT_FLOW,
        new EventHandler("IntrinsicEventIds::PKT_WITHOUT_FLOW")); */

    return true;
  }
};

const InspectApi networkmap_api = {
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "network_mapping",
        "Help map resources in the network based on their comms",
        []() -> Module * { return new NetworkMappingModule; },
        [](Module *m) { delete m; },
    },

    IT_FIRST,
    PROTO_BIT__ALL, // PROTO_BIT__ANY_IP, // PROTO_BIT__ALL, PROTO_BIT__NONE, //
    nullptr,        // buffers
    nullptr,        // service
    nullptr,        // pinit
    nullptr,        // pterm
    nullptr,        // tinit
    nullptr,        // tterm
    [](Module *module) -> Inspector * {
      assert(module);
      return new NetworkMappingInspector(
          dynamic_cast<NetworkMappingModule *>(module));
    },
    [](Inspector *p) { delete p; },
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi *snort_plugins[] = {&networkmap_api.base, nullptr};
