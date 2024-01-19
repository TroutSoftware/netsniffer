#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <list>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>

#include "framework/inspector.h"
#include "framework/module.h"
#include "protocols/eth.h"
#include "protocols/packet.h"
#include "pub_sub/appid_event_ids.h"
#include "pub_sub/http_event_ids.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "sfip/sf_ip.h"
#include "time/periodic.h"

using namespace snort;

bool use_rotate_feature = true;

static const Parameter nm_params[] = {
    {"cache_size", Parameter::PT_INT, "0:max32", "0", "set cache size"},
    {"log_file", Parameter::PT_STRING, nullptr, "flow.txt",
     "set output file name"},
    {"size_rotate", Parameter::PT_BOOL, nullptr, "false",
     "If true rotates log file after x lines"},

    {nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr}};

struct LogFileStats {
  PegCount line_count;
  PegCount file_count;
};

static THREAD_LOCAL LogFileStats s_file_stats;

const PegInfo s_pegs[] = {{CountType::SUM, "lines", "lines written"},
                          {CountType::SUM, "files", "files opened"},

                          {CountType::END, nullptr, nullptr}};

class LogFile {

  std::mutex mutex;
  std::ofstream stream; // Stream logs are written to
  std::string
      base_file_name; // The base filename, i.e. without the timestamp extension
  unsigned log_files_opened = 0; // Count of logfiles that has been opened
  unsigned log_lines_total = 0;  // Total number of log lines written (sum of
                                 // lines written to all files)
  unsigned log_lines_written =
      0; // Number of log lines written in the current file
  const unsigned max_lines_pr_file =
      1'000'000; // When this number of lines has been written a new file will
                 // be written

  // Flush parameters
  const unsigned lines_beween_flushes = 100; // Number of lines between flushes
  unsigned lines_since_last_flush = 0;       // Number of lines since last flush

  enum class State {
    initial, // Initial state
    open,    // File is open and ready for use
    full,    // The current file is full
    aborted  // We have stopped writing to an actual file
  } state = State::initial;

  // TODO(mkr) make a flush based on time too

public:
  void set_file_name(const char *new_name) {
    std::scoped_lock guard(mutex);

    assert(State::initial == state); // We can't set the filename after we have
                                     // started to use the name
    assert(new_name);                // Make sure we got some input

    base_file_name = new_name;
  }

  void log(char prefix, std::string message) noexcept {
    std::scoped_lock guard(mutex);

    switch (state) {
    case State::aborted:
      return;

    case State::full:
      stream.close();
      lines_since_last_flush = 0;

      [[fallthrough]];

    case State::initial: {
      using namespace std::chrono;
      assert(
          !base_file_name
               .empty()); // Logic error if the filename isn't set at this point

      std::string file_name(base_file_name);

      if (use_rotate_feature) {
        const auto cur_time = system_clock::now().time_since_epoch();
        uint64_t cur_time_ms = duration_cast<milliseconds>(cur_time).count();

        file_name += std::to_string(cur_time_ms);
      }

      // We use std::ios_base::app vs. std::ios_base::ate to ensure
      // we don't overwrite data written between our own writes
      stream.open(file_name, std::ios_base::app);

      if (!stream || !stream.is_open()) {
        state = State::aborted;
        return;
      }

      state = State::open;
      s_file_stats.file_count++;
      log_files_opened++;
      log_lines_written = 0;
    }

      [[fallthrough]];

    case State::open:
      // std::cout << "****** Logs: " << prefix << ' ' << message << std::endl;
      stream << prefix << ' ' << message << std::endl;

      s_file_stats.line_count++;
      log_lines_total++;
      log_lines_written++;
      lines_since_last_flush++;

      // TODO(mkr) - validate that a stream with an error, can be closed, and
      // reopened
      if (!stream ||
          (use_rotate_feature && max_lines_pr_file <= log_lines_written)) {
        state = State::full;
      } else if (lines_beween_flushes <= lines_since_last_flush) {
        stream.flush();
        lines_since_last_flush = 0;
      }
    }
  }
};

class Timer {
  static class Ticker {
  public:
    Ticker() {
      Periodic::register_handler([](void *) { Timer::tick(); }, nullptr, 0,
                                 10'000);
    }
  } ticker;

  static void tick() {}

public:
  bool stop_timer() { return true; }

  virtual void timeout() = 0;
};

class NetworkMappingModule : public Module {
  std::shared_ptr<LogFile> logger;

public:
  NetworkMappingModule()
      : Module("network_mapping",
               "Help map resources in the network based on their comms",
               nm_params),
        logger(new LogFile) {}

  std::shared_ptr<LogFile> &get_logger() { return logger; }

  Usage get_usage() const override { return CONTEXT; }

  bool set(const char *, Value &val, SnortConfig *) override {
    if (val.is("log_file") && val.get_string()) {
      logger->set_file_name(val.get_string());
    } else if (val.is("size_rotate")) {
      use_rotate_feature = val.get_bool();
    }

    return true;
  }

  const PegInfo *get_pegs() const override { return s_pegs; }

  PegCount *get_counts() const override { return (PegCount *)&s_file_stats; }
};

class NetworkMappingFlowData : public FlowData, public Timer {
  std::shared_ptr<LogFile> logger;
  std::string timeout_string;

public:
  NetworkMappingFlowData(Inspector *inspector, std::shared_ptr<LogFile> &logger,
                         std::string timeout_string)
      : FlowData(get_id(), inspector), logger(logger),
        timeout_string(timeout_string) {}

  ~NetworkMappingFlowData() {
    /*    if (stop_timer()) {
          logger->log('N', timeout_string);
        }*/
  }

  unsigned static get_id() {
    static unsigned flow_data_id = FlowData::create_flow_data_id();
    return flow_data_id;
  }

  virtual void timeout() override { logger->log('N', timeout_string); }
};

class EventHandler : public DataHandler {
  Inspector *inspector;
  std::shared_ptr<LogFile> logger;
  unsigned event_type;

  void append_MAC(std::stringstream &ss, const uint8_t *mac,
                  const size_t mac_size) {
    assert(mac_size == 6);

    ss << std::hex << std::setfill('0') << std::setw(2) << +(mac[0]) << ':'
       << std::setw(2) << +(mac[1]) << ':' << std::setw(2) << +(mac[2]) << ':'
       << std::setw(2) << +(mac[3]) << ':' << std::setw(2) << +(mac[4]) << ':'
       << std::setw(2) << +(mac[5]);
  }

public:
  EventHandler(Inspector *inspector, std::shared_ptr<LogFile> &logger,
               unsigned event_type)
      : DataHandler("network_mapping"), inspector(inspector), logger(logger),
        event_type(event_type){};

  void handle(DataEvent &de, Flow *flow) override {

    NetworkMappingFlowData *flow_data = nullptr;

    std::stringstream ss;
    const Packet *p = de.get_packet();

    assert(p);

    const eth::EtherHdr *eh =
        ((p->proto_bits & PROTO_BIT__ETH) ? layer::get_eth_layer(p) : nullptr);
    const bool has_ip = p->has_ip();
    const bool has_ipv6 = p->is_ip6();
    const bool has_port = p->is_tcp() || p->is_udp();

    // add one of IP, MAC, '-' (in that priority) to ss for the src parameter
    if (has_ip) {
      char ip_str[INET6_ADDRSTRLEN];
      sfip_ntop(p->ptrs.ip_api.get_src(), ip_str, sizeof(ip_str));

      if (has_ipv6) {
        ss << '[' << ip_str << ']';
      } else {
        ss << ip_str;
      }

      if (has_port) {
        ss << ':' << p->ptrs.sp;
      } else {
        ss << ':' << '-';
      }

    } else if (eh) {
      append_MAC(ss, eh->ether_src, sizeof(eh->ether_src));
    } else {
      ss << '-';
    }

    ss << " -> ";

    if (has_ip) {
      char ip_str[INET6_ADDRSTRLEN];
      sfip_ntop(p->ptrs.ip_api.get_dst(), ip_str, sizeof(ip_str));

      if (has_ipv6) {
        ss << '[' << ip_str << ']';
      } else {
        ss << ip_str;
      }

      if (has_port) {
        ss << ':' << p->ptrs.dp;
      } else {
        ss << ':' << '-';
      }
    } else if (eh) {
      append_MAC(ss, eh->ether_dst, sizeof(eh->ether_dst));
    } else {
      ss << '-';
    }

    if (flow) {
      flow_data = dynamic_cast<NetworkMappingFlowData *>(
          flow->get_flow_data(NetworkMappingFlowData::get_id()));

      if (!flow_data) {
        flow_data = new NetworkMappingFlowData(inspector, logger, ss.str());
        flow->set_flow_data(flow_data);
      }
    }

    // TODO(mkr) add counters/pegs
    switch (event_type) {
    case IntrinsicEventIds::FLOW_SERVICE_CHANGE: {
      assert(flow_data);
      char prefix = flow_data->stop_timer() ? 'N' : 'U';
      ss << ' ' << ((flow && flow->service) ? flow->service : "-");

      logger->log(prefix, ss.str());
    } break;

    case IntrinsicEventIds::FLOW_STATE_SETUP:
      break;

    case IntrinsicEventIds::FLOW_STATE_RELOADED:
      break;

    case IntrinsicEventIds::PKT_WITHOUT_FLOW:
      ss << " -";
      logger->log('N', ss.str());
      break;

    case IntrinsicEventIds::FLOW_NO_SERVICE:
      ss << " -";
      logger->log('N', ss.str());
      break;
    }
  }

private:
  // TODO(mkr) Look for snort function for the convertion
  const char *get_event_name(unsigned event_type) {
    switch (event_type) {
    case IntrinsicEventIds::FLOW_SERVICE_CHANGE:
      return "FLOW_SERVICE_CHANGE";

    case IntrinsicEventIds::FLOW_STATE_SETUP:
      return "FLOW_STATE_SETUP";

    case IntrinsicEventIds::FLOW_STATE_RELOADED:
      return "FLOW_STATE_RELOADED";

    case IntrinsicEventIds::PKT_WITHOUT_FLOW:
      return "PKT_WITHOUT_FLOW";

    case IntrinsicEventIds::FLOW_NO_SERVICE:
      return "FLOW_NO_SERVICE";

    default:
      assert(false);
      return "Update EventHandler::get_event_name() to get name";
    }
  }
};

class NetworkMappingInspector : public Inspector {
  std::shared_ptr<LogFile> logger;

public:
  NetworkMappingInspector(NetworkMappingModule *module)
      : logger(module->get_logger()) {}

  void eval(Packet *) override {}

  bool configure(SnortConfig *) override {
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::FLOW_SERVICE_CHANGE,
        new EventHandler(this, logger, IntrinsicEventIds::FLOW_SERVICE_CHANGE));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::FLOW_STATE_SETUP,
        new EventHandler(this, logger, IntrinsicEventIds::FLOW_STATE_SETUP));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::FLOW_STATE_RELOADED,
        new EventHandler(this, logger, IntrinsicEventIds::FLOW_STATE_RELOADED));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::PKT_WITHOUT_FLOW,
        new EventHandler(this, logger, IntrinsicEventIds::PKT_WITHOUT_FLOW));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::FLOW_NO_SERVICE,
        new EventHandler(this, logger, IntrinsicEventIds::FLOW_NO_SERVICE));

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

    IT_PASSIVE,
    PROTO_BIT__ALL,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
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
