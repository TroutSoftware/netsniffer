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

  void log(char prefix, std::string message, bool noRotate = false) noexcept {
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
      if (!stream || (use_rotate_feature && !noRotate &&
                      max_lines_pr_file <= log_lines_written)) {
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

  struct M {
    std::mutex mutex;
    std::vector<Timer *> timer_list;
  };

  static M &get_m() {
    static M m;
    return m;
  }

  static void tick() {
    std::scoped_lock guard(get_m().mutex);
    for (auto p : get_m().timer_list) {
      p->timeout();
    }
  }

public:
  Timer() {
    std::scoped_lock guard(get_m().mutex);
    get_m().timer_list.emplace_back(this);
  }

  ~Timer() {
    if (stop_timer()) {
      // If the element is in the list when we are destroyed, we have a
      // potential racecondition between the destruction and calls to timeout,
      // as the object inheriting from us would in the process of being
      // destroyed
      assert(false);
    }
  }

  // Returns true if the timer was previous running, false if not
  bool stop_timer() {
    std::scoped_lock guard(get_m().mutex);
    return (0 != std::erase(get_m().timer_list, this));
  }

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

class StringGenerators {

  static void append_MAC(std::stringstream &ss,
                         const std::array<uint8_t, 6> &mac) {

    ss << std::hex << std::setfill('0') << std::setw(2) << +(mac.at(0)) << ':'
       << std::setw(2) << +(mac.at(1)) << ':' << std::setw(2) << +(mac.at(2))
       << ':' << std::setw(2) << +(mac.at(3)) << ':' << std::setw(2)
       << +(mac.at(4)) << ':' << std::setw(2) << +(mac.at(5));
  }

public:
  static void append_IP_MAC(std::stringstream &ss, const Packet *p,
                            bool is_src) {

    if (p->has_ip()) {
      const SfIp *sf_ip =
          (is_src ? p->ptrs.ip_api.get_src() : p->ptrs.ip_api.get_dst());
      char ip_str[INET6_ADDRSTRLEN];

      sfip_ntop(sf_ip, ip_str, sizeof(ip_str));

      if (p->is_ip6()) {
        ss << '[' << ip_str << ']';
      } else {
        ss << ip_str;
      }

      if (p->is_tcp() || p->is_udp()) {
        ss << ':' << (is_src ? p->ptrs.sp : p->ptrs.dp);
      } else {
        ss << ':' << '-';
      }
    } else {
      const eth::EtherHdr *eh =
          ((p->proto_bits & PROTO_BIT__ETH) ? layer::get_eth_layer(p)
                                            : nullptr);

      if (eh) {
        const auto mac = std::to_array<const uint8_t>(is_src ? eh->ether_src
                                                             : eh->ether_dst);
        append_MAC(ss, mac);

      } else {
        ss << '-';
      }
    }
  }
};

class NetworkMappingPendingData {
  // Protected members
  struct {
    std::mutex mutex;
    std::vector<std::string> services;
  } m;

  const std::shared_ptr<NetworkMappingPendingData> next;
  // Note: we store a formated addr string "src[:port] -> dest[:port]" instead
  // of the raw data from the packet, as the data is full of pointers to things
  // we don't know the life time of, so we generate the string rather than a
  // complex/selective copy
  const std::string addr_str;

  std::string format_string(const Packet *p) {
    assert(p);
    std::stringstream ss;

    StringGenerators::append_IP_MAC(ss, p, true);
    ss << " -> ";
    StringGenerators::append_IP_MAC(ss, p, false);

    return ss.str();
  }

public:
  NetworkMappingPendingData(const Packet *p,
                            std::shared_ptr<NetworkMappingPendingData> next)
      : next(next), addr_str(format_string(p)) {}

  std::shared_ptr<NetworkMappingPendingData> get_next() { return next; }

  static void add_service_name(std::weak_ptr<NetworkMappingPendingData> weak,
                               const char *service_name) {
    assert(service_name && *service_name);

    auto shared = weak.lock();

    if (shared) {
      std::scoped_lock guard(shared->m.mutex);
      // TODO(mkr): Store these in a more efficient way
      shared->m.services.emplace_back(service_name);
    }
  }

  const std::string &get_addr_str() { return addr_str; }

  void write_to_log(LogFile &logger) {
    std::scoped_lock guard(m.mutex);
    if (m.services.empty()) {
      std::string output = addr_str + " - ";
      logger.log('N', output);
    } else {
      auto remains = m.services.size();
      bool once = true;
      for (auto ele : m.services) {
        std::string output = addr_str + ' ' + ele;
        logger.log((once ? 'N' : 'U'), output, !--remains);
        once = false;
      }
    }
  }
};

class NetworkMappingFlowData : public FlowData, public Timer {
  std::weak_ptr<NetworkMappingPendingData>
      pending; // Using weak_ptr as we are not the owner of the object
  const std::shared_ptr<LogFile> logger;
  std::string timeout_string;

public:
  NetworkMappingFlowData(Inspector *inspector,
                         const std::shared_ptr<LogFile> &logger,
                         std::string timeout_string,
                         std::weak_ptr<NetworkMappingPendingData> pending)
      : FlowData(get_id(), inspector), pending(pending), logger(logger),
        timeout_string(timeout_string) {}

  ~NetworkMappingFlowData() {
    stop_timer();
    /*    if (stop_timer()) {
          logger->log('N', timeout_string);
        }*/
  }

  void add_service_name(const char *service_name) {
    NetworkMappingPendingData::add_service_name(pending, service_name);
  }

  unsigned static get_id() {
    static unsigned flow_data_id = FlowData::create_flow_data_id();
    return flow_data_id;
  }

  virtual void timeout() override { /*logger->log('N', timeout_string);*/ }
};

class NetworkMappingInspector : public Inspector, private Timer {
  const std::shared_ptr<LogFile> logger;

  struct {
    std::mutex mutex;
    std::shared_ptr<NetworkMappingPendingData>
        gathering; // Where we collect entries
    std::shared_ptr<NetworkMappingPendingData>
        aging; // Where we let them age for 10s
  } m;

  virtual void timeout() override {
    std::shared_ptr<NetworkMappingPendingData> expirering;

    {
      std::scoped_lock guard(m.mutex);
      expirering = m.aging;
      m.aging = m.gathering;
    }

    while (expirering) {
      expirering->write_to_log(*logger.get());
      expirering = expirering->get_next();
    }
  }

  void flush_pending() {
    // Simulate two timeouts to get all queued data out
    timeout();
    timeout();
  }

public:
  NetworkMappingInspector(NetworkMappingModule *module)
      : logger(module->get_logger()) {}

  ~NetworkMappingInspector() {
    // We need to ensure the timer doesn't fire after we are torn down
    stop_timer();

    flush_pending();
  }

  std::weak_ptr<NetworkMappingPendingData> addPendingData(const Packet *p) {
    std::scoped_lock guard(m.mutex);
    // TODO(mkr) add counter and flush if more than max counter is stored
    m.gathering = std::make_shared<NetworkMappingPendingData>(p, m.gathering);
    return m.gathering;
  }

  void eval(Packet *) override {}

  bool configure(SnortConfig *) override;
};

class EventHandler : public DataHandler {
  NetworkMappingInspector *inspector;
  const std::shared_ptr<LogFile> logger;
  unsigned event_type;

public:
  EventHandler(NetworkMappingInspector *inspector,
               const std::shared_ptr<LogFile> &logger, unsigned event_type)
      : DataHandler("network_mapping"), inspector(inspector), logger(logger),
        event_type(event_type){};

  void handle(DataEvent &de, Flow *flow) override {

    NetworkMappingFlowData *flow_data = nullptr;

    std::stringstream ss;
    const Packet *p = de.get_packet();

    assert(p);

//    StringGenerators::append_IP_MAC(ss, p, true);
//    ss << " -> ";
//    StringGenerators::append_IP_MAC(ss, p, false);

    if (flow) {
      flow_data = dynamic_cast<NetworkMappingFlowData *>(
          flow->get_flow_data(NetworkMappingFlowData::get_id()));

      if (!flow_data) {
        flow_data = new NetworkMappingFlowData(inspector, logger, ss.str(),
                                               inspector->addPendingData(p));

        flow->set_flow_data(flow_data);
      }
    }

    // TODO(mkr) add counters/pegs
    switch (event_type) {
    case IntrinsicEventIds::FLOW_SERVICE_CHANGE: {
      assert(flow_data);

      if (flow && flow->service)
        flow_data->add_service_name(flow->service);

//      char prefix = flow_data->stop_timer() ? 'N' : 'U';
//      ss << ' ' << ((flow && flow->service) ? flow->service : "-");

//      logger->log(prefix, ss.str());
    } break;

    case IntrinsicEventIds::FLOW_STATE_SETUP:
      break;

    case IntrinsicEventIds::FLOW_STATE_RELOADED:
      break;

    case IntrinsicEventIds::PKT_WITHOUT_FLOW:

//      ss << " -";
//      logger->log('N', ss.str());
      if (!flow_data) {
        inspector->addPendingData(p);
      }
      break;

    case IntrinsicEventIds::FLOW_NO_SERVICE:
      assert(flow_data);
//      ss << " -";
//      logger->log('N', ss.str());
      break;
    }
  }
};

bool NetworkMappingInspector::configure(SnortConfig *) {
  DataBus::subscribe_network(
      intrinsic_pub_key, IntrinsicEventIds::FLOW_SERVICE_CHANGE,
      new EventHandler(this, logger, IntrinsicEventIds::FLOW_SERVICE_CHANGE));
  /*    DataBus::subscribe_network(
          intrinsic_pub_key, IntrinsicEventIds::FLOW_STATE_SETUP,
          new EventHandler(this, logger,
     IntrinsicEventIds::FLOW_STATE_SETUP));*/
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
