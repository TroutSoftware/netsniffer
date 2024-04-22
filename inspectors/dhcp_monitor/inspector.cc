
#include <iostream>
#include <shared_mutex>

#include "framework/inspector.h"
#include "framework/module.h"
#include "protocols/packet.h"
#include "pub_sub/appid_event_ids.h"
#include "pub_sub/dhcp_events.h"
#include "pub_sub/intrinsic_event_ids.h"

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

struct DHCPStats {
  PegCount info_count;
  PegCount check_count;
  PegCount update_count;
  PegCount network_count;
  PegCount unknown_count;
  PegCount no_ip_count;
  PegCount src_dst_ip_err_count;
  PegCount ip_pass_count;
};

static THREAD_LOCAL DHCPStats s_dhcp_stats = {0, 0, 0, 0, 0, 0, 0, 0};

const PegInfo s_pegs[] = {
    {CountType::SUM, "info_event", "info events received"},
    {CountType::SUM, "checks_done", "number of checks done"},
    {CountType::SUM, "network_update", "network address updates"},
    {CountType::SUM, "network_set", "network address's"},
    {CountType::SUM, "unknown_network", "unknown network used"},
    {CountType::SUM, "no_ip", "no ip in (stream) packet"},
    {CountType::SUM, "src_dst_ipv4_err",
     "either not ipV4 or src or dst ip missing"},
    {CountType::SUM, "ip_pass", "ip's seen within range"},

    {CountType::END, nullptr, nullptr}};

class DHCPMonitorModule : public Module {

public:
  DHCPMonitorModule()
      : Module("dhcp_monitor",
               "Monitors DHCP comunication looking for unexpected use of "
               "network addresss",
               nm_params) {}

  Usage get_usage() const override { return CONTEXT; }

  bool set(const char *, Value &, SnortConfig *) override { return true; }

  const PegInfo *get_pegs() const override { return s_pegs; }

  PegCount *get_counts() const override { return (PegCount *)&s_dhcp_stats; }
};

class DHCPMonitorInspector : public Inspector {
  class DHCPRecord {
    uint32_t network_address;
    uint32_t network_mask;

  public:
    DHCPRecord(uint32_t network_address, uint32_t network_mask)
        : network_address(network_address), network_mask(network_mask) {
      s_dhcp_stats.network_count++;
    }

    bool validate(uint32_t ip_address) {
      s_dhcp_stats.check_count++;
      return network_address == (ip_address & network_mask);
    }

    uint32_t get_network_address() { return network_address; }
    uint32_t get_network_mask() { return network_mask; }

    void update(uint32_t network_address, uint32_t network_mask) {
      s_dhcp_stats.update_count++;
      this->network_address = network_address;
      this->network_mask = network_mask;
    }
  };

  struct {
    std::shared_mutex mutex;
    std::map<uint32_t, DHCPRecord> map;
  } network;

  // Must be called with the network.mutex taken if the record is from the
  // network member
  void validate(uint32_t ip, DHCPRecord &record) {
    if (!record.validate(ip)) {
      flag_ip_conflict(ip, record);
    } else {
      s_dhcp_stats.ip_pass_count++;
    }
  }

public:
  DHCPMonitorInspector(DHCPMonitorModule *) {}

  ~DHCPMonitorInspector() {}

  void eval(Packet *) override {}

  bool configure(SnortConfig *) override;

  void flag_ip_conflict(uint32_t ip, DHCPRecord &record) {
    std::cout << "*** MKR test - IP Conflict flagged for"
              << "          ip: " << inet_ntoa((in_addr)ip) << " networkaddr: "
              << inet_ntoa((in_addr)record.get_network_address())
              << " networkmask: "
              << inet_ntoa((in_addr)record.get_network_mask()) << std::endl;
  }

  void flag_dhcp_conflict(uint32_t ip, DHCPRecord &record) {
    std::cout << "*** MKR test - DHCP Conflict flagged for"
              << "          ip: " << inet_ntoa((in_addr)ip) << " networkaddr: "
              << inet_ntoa((in_addr)record.get_network_address())
              << " networkmask: "
              << inet_ntoa((in_addr)record.get_network_mask()) << std::endl;
  }

  void flag_unknown_network(uint32_t ip, uint32_t network) {
    std::cout << "*** MKR test - Missing configuration info for network"
              << "          ID: " << network
              << "          ip: " << inet_ntoa((in_addr)ip) << std::endl;

    s_dhcp_stats.unknown_count++;
  }

  void validate(uint32_t ip) {
    std::shared_lock lock(network.mutex);

    auto record = network.map.find(1);

    if (record == network.map.end()) {
      flag_unknown_network(ip, 1);
    } else {
      validate(ip, record->second);
    }
  }

  void add_ip_mask(uint32_t ip, uint32_t network_mask) {
    std::unique_lock lock(network.mutex);

    // For now we hardcode our map key to 1

    // Check if record exists
    auto record = network.map.find(1);

    if (record == network.map.end()) {
      network.map.emplace(
          std::make_pair(1, DHCPRecord(ip & network_mask, network_mask)));
    } else {
      if (record->second.get_network_mask() != network_mask ||
          !record->second.validate(ip)) {
        flag_dhcp_conflict(ip, record->second);
        record->second.update(ip & network_mask, network_mask);
      }
    }
  }
};

class DHCPInfoEventHandler : public DataHandler {
  DHCPMonitorInspector *inspector;

public:
  DHCPInfoEventHandler(DHCPMonitorInspector *inspector)
      : DataHandler("dhcp_monitor"), inspector(inspector) {
    assert(inspector);
  };

  void handle(DataEvent &event, Flow *) override {
    s_dhcp_stats.info_count++;

    DHCPInfoEvent &dhcp_info_event = dynamic_cast<DHCPInfoEvent &>(
        event); // NOTE: Will throw bad_cast exception if failing
#if 1
    std::cout << "***MKR TEST got DHCP_INFO" << std::endl;

    std::cout << "***  ip: "
              << inet_ntoa((in_addr)dhcp_info_event.get_ip_address())
              << std::endl;
    // std::cout << "***  eth addr: " << dhcp_info_event.get_eth_addr() <<
    // std::endl; //const uint8_t* get_eth_addr() const
    /*
    std::cout << "***  eth addr: " << std::hex <<
    dhcp_info_event.get_eth_addr()[0] << ":"
                                   << dhcp_info_event.get_eth_addr()[1] << ":"
                                   << dhcp_info_event.get_eth_addr()[2] << ":"
                                   << dhcp_info_event.get_eth_addr()[3] << ":"
                                   << dhcp_info_event.get_eth_addr()[4] << ":"
                                   << dhcp_info_event.get_eth_addr()[5] <<
    std::endl;
*/
    std::cout << "***  subnet: "
              << inet_ntoa(
                     (in_addr)htonl(dhcp_info_event.get_subnet_mask())) // ntohl
              << std::endl;
    std::cout << "***  lease: " << dhcp_info_event.get_lease_secs()
              << " seconds" << std::endl;
    std::cout << "***  router: "
              << inet_ntoa((in_addr)dhcp_info_event.get_router()) << std::endl;
#endif
    inspector->add_ip_mask(dhcp_info_event.get_ip_address(),
                           htonl(dhcp_info_event.get_subnet_mask()));
    inspector->validate(dhcp_info_event.get_router());
  }
};

class EventHandler : public DataHandler {
  DHCPMonitorInspector *inspector;
  unsigned event_type;

public:
  EventHandler(DHCPMonitorInspector *inspector, unsigned event_type)
      : DataHandler("dhcp_monitor"), inspector(inspector),
        event_type(event_type) {
    assert(inspector);
  };

  void handle(DataEvent &event, Flow *) override {

    const Packet *p = event.get_packet();

    // Bail if no packet, or packet don't have ip
    if (!p || !p->has_ip()) {
      s_dhcp_stats.no_ip_count++;
      return;
    }

    // std::cout << "*** MKR TEST Packet have ip" << std::endl;

    const SfIp *src = p->ptrs.ip_api.get_src();
    const SfIp *dst = p->ptrs.ip_api.get_dst();

    if (!src || !src->is_ip4() || !dst || !dst->is_ip4()) {
      s_dhcp_stats.src_dst_ip_err_count++;
      return;
    }

    char ip_src[INET6_ADDRSTRLEN];
    char ip_dst[INET6_ADDRSTRLEN];
    sfip_ntop(src, ip_src, sizeof(ip_src));
    sfip_ntop(dst, ip_dst, sizeof(ip_dst));

    //    if (sf_ip->is_ip6()) {

    //    std::cout << "*** MKR TEST src: " << ip_src << " dst: " << ip_dst
    //              << std::endl;

    inspector->validate(src->get_ip4_value());
    inspector->validate(dst->get_ip4_value());

    //    bool has_ip() const
    //{ return ptrs.ip_api.is_ip(); }
  }
};

bool DHCPMonitorInspector::configure(SnortConfig *) {
  DataBus::subscribe_network(appid_pub_key, AppIdEventIds::DHCP_INFO,
                             new DHCPInfoEventHandler(this));
  // DataBus::subscribe_network(appid_pub_key, AppIdEventIds::DHCP_DATA, new
  // EventHandler(this, AppIdEventIds::DHCP_DATA));
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

const InspectApi dhcpmonitor_api = {
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "dhcp_monitor",
        "Monitors use of network addresses and DHCP requests",
        []() -> Module * { return new DHCPMonitorModule; },
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
      return new DHCPMonitorInspector(
          dynamic_cast<DHCPMonitorModule *>(module));
    },
    [](Inspector *p) { delete p; },
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi *snort_plugins[] = {&dhcpmonitor_api.base, nullptr};
