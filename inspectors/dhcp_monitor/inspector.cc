
#include <iostream>

#include "framework/inspector.h"
#include "framework/module.h"
#include "protocols/packet.h"
#include "pub_sub/appid_event_ids.h"

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
  PegCount data_count;
};

static THREAD_LOCAL DHCPStats s_dhcp_stats = {0, 0};

const PegInfo s_pegs[] = {{CountType::SUM, "info", "info events received"},
                          {CountType::SUM, "data", "data events received"},

                          {CountType::END, nullptr, nullptr}};

class DHCPMonitorModule : public Module {

public:
  DHCPMonitorModule()
      : Module("dhcp_monitor",
               "Monitors DHCP comunication looking for unexpected use of "
               "network addresss",
               nm_params) {}

  Usage get_usage() const override { return CONTEXT; }

  bool set(const char *, Value &val, SnortConfig *) override {
    if (val.is("log_file") && val.get_string()) {

    } else if (val.is("size_rotate")) {

    } else if (val.is("connection_cache_size")) {

    } else if (val.is("noflow_log")) {
    }

    return true;
  }

  const PegInfo *get_pegs() const override { return s_pegs; }

  PegCount *get_counts() const override { return (PegCount *)&s_dhcp_stats; }
};

class DHCPMonitorInspector : public Inspector {

public:
  DHCPMonitorInspector(DHCPMonitorModule *) {}

  ~DHCPMonitorInspector() {}

  void eval(Packet *) override {}

  bool configure(SnortConfig *) override;
};

class EventHandler : public DataHandler {
  DHCPMonitorInspector *inspector;
  unsigned event_type;

public:
  EventHandler(DHCPMonitorInspector *inspector, unsigned event_type)
      : DataHandler("dhcp_monitor"), inspector(inspector),
        event_type(event_type){};

  void handle(DataEvent &, Flow *) override {

    switch (event_type) {
    case AppIdEventIds::DHCP_INFO: {
      std::cout << "***MKR TEST got DHCP_INFO" << std::endl;
      s_dhcp_stats.info_count++;
    } break;

    case AppIdEventIds::DHCP_DATA: {
      std::cout << "***MKR TEST got DHCP_DATA" << std::endl;
      s_dhcp_stats.data_count++;
    } break;

    default: {
      std::cout << "***MKR TEST got unspecified event: " << event_type
                << std::endl;
    }
    }
  }
};

bool DHCPMonitorInspector::configure(SnortConfig *) {
  DataBus::subscribe_network(appid_pub_key, AppIdEventIds::DHCP_INFO,
                             new EventHandler(this, AppIdEventIds::DHCP_INFO));
  DataBus::subscribe_network(appid_pub_key, AppIdEventIds::DHCP_DATA,
                             new EventHandler(this, AppIdEventIds::DHCP_DATA));

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
