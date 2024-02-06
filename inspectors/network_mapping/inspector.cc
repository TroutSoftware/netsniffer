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
bool log_noflow_packages = false;

unsigned connection_cache_size = 0;

static const Parameter nm_params[] = {
    {"connection_cache_size", Parameter::PT_INT, "0:max32", "100000",
     "set cache size pr inspector, unit is number of connections"},
    {"log_file", Parameter::PT_STRING, nullptr, "flow.txt",
     "set output file name"},
    {"size_rotate", Parameter::PT_BOOL, nullptr, "false",
     "If true rotates log file after x lines"},
    {"noflow_log", Parameter::PT_BOOL, nullptr, "false",
     "If true also logs no flow packages"},

    {nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr}};

struct LogFileStats {
  PegCount line_count;
  PegCount file_count;
  //  PegCount flow_count;
  //  PegCount service_count;
  PegCount connection_cache_max;
  PegCount connection_cache_flush;
};

static THREAD_LOCAL LogFileStats s_file_stats = {0, 0, /*0, 0,*/ 0, 0};

const PegInfo s_pegs[] = {
    {CountType::SUM, "lines", "lines written"},
    {CountType::SUM, "files", "files opened"},
    //    {CountType::SUM, "flows", "number of flows detected"},
    //    {CountType::SUM, "services", "number of services detected"},
    {CountType::MAX, "connections cache max", "max cache usage"},
    {CountType::SUM, "cache flushes", "number of forced cache flushes"},

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

  // TODO(mkr) make a flush based on time too, or maybe just let the code call a
  // flush each time an inspector has dumped the work of the last 10s

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
  class Ticker {
  public:
    Ticker() {
      Periodic::register_handler([](void *) { Timer::tick(); }, nullptr, 0,
                                 10'000);
    }
  };

  Ticker &get_ticker() {
    static Ticker ticker;
    return ticker;
  };

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
    get_ticker();
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
    } else if (val.is("connection_cache_size")) {
      connection_cache_size = val.get_int32();
    } else if (val.is("noflow_log")) {
      log_noflow_packages = val.get_bool();
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

  static void append_sf_ip(std::stringstream &ss, const SfIp *sf_ip) {
    char ip_str[INET6_ADDRSTRLEN];

    sfip_ntop(sf_ip, ip_str, sizeof(ip_str));

    if (sf_ip->is_ip6()) {
      ss << '[' << ip_str << ']';
    } else {
      ss << ip_str;
    }
  }

public:
  static std::string format_IP_MAC(const Packet *p, const Flow *flow,
                                   bool is_src) {
    std::stringstream ss;
    if (flow) {
      const SfIp &sf_ip = (is_src ? flow->client_ip : flow->server_ip);
      const uint16_t port = (is_src ? flow->client_port : flow->server_port);

      append_sf_ip(ss, &sf_ip);
      ss << ':' << +port;
    } else if (p->has_ip()) {
      const SfIp *sf_ip =
          (is_src ? p->ptrs.ip_api.get_src() : p->ptrs.ip_api.get_dst());

      append_sf_ip(ss, sf_ip);

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
    return ss.str();
  }
};

class NetworkMappingPendingData {
  struct {
    std::mutex mutex;
    std::string first_service;
    std::unique_ptr<std::vector<std::string>> services;
    std::string src_str;
    std::string dst_str;
  } m;

  const std::shared_ptr<NetworkMappingPendingData> next;

public:
  NetworkMappingPendingData(const Packet *p, const Flow *flow,
                            std::shared_ptr<NetworkMappingPendingData> next)
      : next(next) {
    update_src_dst(p, flow);
  }

  void update_src_dst(const Packet *p, const Flow *flow) {
    std::scoped_lock guard(m.mutex);
    m.src_str = StringGenerators::format_IP_MAC(p, flow, true);
    m.dst_str = StringGenerators::format_IP_MAC(p, flow, false);
  }

  std::shared_ptr<NetworkMappingPendingData> get_next() { return next; }

  static void add_service_name(std::weak_ptr<NetworkMappingPendingData> weak,
                               const char *service_name) {
    assert(service_name && *service_name);

    auto shared = weak.lock();

    if (shared) {
      std::scoped_lock guard(shared->m.mutex);

      if (shared->m.first_service.empty()) {
        shared->m.first_service = service_name;
      } else {
        if (!shared->m.services) {
          shared->m.services = std::make_unique<std::vector<std::string>>();
        }
        shared->m.services->emplace_back(service_name);
      }
    }
  }

  static void update_src_dst(std::weak_ptr<NetworkMappingPendingData> weak,
                             const Packet *p, const Flow *flow) {
    assert(p);

    auto shared = weak.lock();

    if (shared) {
      shared->update_src_dst(p, flow);
    }
  }

  void write_to_log(LogFile &logger) {
    const static char *arrow = " -> ";
    // Used to ensure that we don't have logs from multiple writes intermixed
    static std::mutex log_write_mutex;

    std::scoped_lock guard(m.mutex, log_write_mutex);
    if (m.first_service.empty()) {
      std::string output = m.src_str + arrow + m.dst_str + " - ";
      logger.log('N', output);
    } else {
      std::string addr_port = m.src_str + arrow + m.dst_str + ' ';
      std::string output = addr_port + m.first_service;
      logger.log('N', output, !!m.services);

      if (m.services) {
        auto remains = m.services->size();

        for (auto ele : *m.services) {
          output = addr_port + ele;
          logger.log('U', output, !--remains);
        }
      }
    }
  }
};

class NetworkMappingFlowData : public FlowData {
  // Using weak_ptr as we are not the owner of the object
  std::weak_ptr<NetworkMappingPendingData> pending;

public:
  NetworkMappingFlowData(Inspector *inspector,
                         std::weak_ptr<NetworkMappingPendingData> pending)
      : FlowData(get_id(), inspector), pending(pending) {}

  void add_service_name(const char *service_name) {
    NetworkMappingPendingData::add_service_name(pending, service_name);
  }

  void update_src_dst(const Packet *p, const Flow *flow) {
    NetworkMappingPendingData::update_src_dst(pending, p, flow);
  }

  unsigned static get_id() {
    static unsigned flow_data_id = FlowData::create_flow_data_id();
    return flow_data_id;
  }
};

class NetworkMappingInspector : public Inspector, private Timer {
  const std::shared_ptr<LogFile> logger;

  struct {
    std::mutex mutex;
    std::shared_ptr<NetworkMappingPendingData>
        gathering; // Where we collect entries
    unsigned gathering_count = 0;
    std::shared_ptr<NetworkMappingPendingData>
        aging; // Where we let them age for 10s
    unsigned aging_count = 0;
  } m;

  virtual void timeout() override {
    std::shared_ptr<NetworkMappingPendingData> expirering;

    {
      std::scoped_lock guard(m.mutex);
      expirering = m.aging;
      m.aging = m.gathering;
      m.aging_count = m.gathering_count;
      m.gathering.reset();
      m.gathering_count = 0;
      s_file_stats.connection_cache_flush++;
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

  std::weak_ptr<NetworkMappingPendingData> addPendingData(const Packet *p,
                                                          Flow *flow) {
    bool flush = false;
    std::weak_ptr<NetworkMappingPendingData> weak;

    // TODO(mkr): Should we improve this, we can risk multiple thread are
    // processing at the same time, making us overshoot the cache limit - this
    // will also lead to multiple flushes

    {
      std::scoped_lock guard(m.mutex);
      m.gathering =
          std::make_shared<NetworkMappingPendingData>(p, flow, m.gathering);
      weak = m.gathering;
      auto sum = m.aging_count + ++m.gathering_count;
      flush = sum >= connection_cache_size;
      if (sum > s_file_stats.connection_cache_max) {
        s_file_stats.connection_cache_max = sum;
      }
    }

    if (flush) {
      timeout();
    };

    return weak;
  }

  void eval(Packet *) override {}

  bool configure(SnortConfig *) override;
};

class EventHandler : public DataHandler {
  NetworkMappingInspector *inspector;
  unsigned event_type;

public:
  EventHandler(NetworkMappingInspector *inspector, unsigned event_type)
      : DataHandler("network_mapping"), inspector(inspector),
        event_type(event_type){};

  void handle(DataEvent &de, Flow *flow) override {

    NetworkMappingFlowData *flow_data = nullptr;

    std::stringstream ss;
    const Packet *p = de.get_packet();

    assert(p);

    if (flow) {
      flow_data = dynamic_cast<NetworkMappingFlowData *>(
          flow->get_flow_data(NetworkMappingFlowData::get_id()));

      if (flow_data) {
        flow_data->update_src_dst(p, flow);
      } else {
        flow_data = new NetworkMappingFlowData(
            inspector, inspector->addPendingData(p, flow));

        flow->set_flow_data(flow_data);
      }
    }

    // TODO(mkr) add counters/pegs
    switch (event_type) {
    case IntrinsicEventIds::FLOW_SERVICE_CHANGE: {
      assert(flow_data);

      if (flow && flow->service) {
        flow_data->add_service_name(flow->service);
      }
    } break;

    case IntrinsicEventIds::FLOW_STATE_SETUP:
      break;

    case IntrinsicEventIds::FLOW_STATE_RELOADED:
      break;

    case IntrinsicEventIds::PKT_WITHOUT_FLOW:
      if (!flow_data && log_noflow_packages) {
        inspector->addPendingData(p, nullptr);
      }
      break;

    case IntrinsicEventIds::FLOW_NO_SERVICE:
      assert(flow_data);
      break;
    }
  }
};

bool NetworkMappingInspector::configure(SnortConfig *) {
  DataBus::subscribe_network(
      intrinsic_pub_key, IntrinsicEventIds::FLOW_SERVICE_CHANGE,
      new EventHandler(this, IntrinsicEventIds::FLOW_SERVICE_CHANGE));
  DataBus::subscribe_network(
      intrinsic_pub_key, IntrinsicEventIds::FLOW_STATE_SETUP,
      new EventHandler(this, IntrinsicEventIds::FLOW_STATE_SETUP));
  DataBus::subscribe_network(
      intrinsic_pub_key, IntrinsicEventIds::FLOW_STATE_RELOADED,
      new EventHandler(this, IntrinsicEventIds::FLOW_STATE_RELOADED));
  DataBus::subscribe_network(
      intrinsic_pub_key, IntrinsicEventIds::PKT_WITHOUT_FLOW,
      new EventHandler(this, IntrinsicEventIds::PKT_WITHOUT_FLOW));
  DataBus::subscribe_network(
      intrinsic_pub_key, IntrinsicEventIds::FLOW_NO_SERVICE,
      new EventHandler(this, IntrinsicEventIds::FLOW_NO_SERVICE));

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
