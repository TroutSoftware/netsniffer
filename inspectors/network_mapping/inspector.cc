//#include <expected>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>

#include "framework/inspector.h"
#include "framework/module.h"
#include "protocols/packet.h"
#include "pub_sub/appid_event_ids.h"
#include "pub_sub/http_event_ids.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "sfip/sf_ip.h"

using namespace snort;

enum class file_error { success, uninitialized_file, cannot_write };

static const Parameter nm_params[] = {
    {"cache_size", Parameter::PT_INT, "0:max32", "0", "set cache size"},
    {"log_file", Parameter::PT_STRING, nullptr, "flow.txt",
     "set output file name"},

    {nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr}};

class NetworkMappingModule : public Module {
public:
  NetworkMappingModule()
      : Module("network_mapping",
               "Help map resources in the network based on their comms",
               nm_params),
        logfile(), logfile_mx() {}
  std::ofstream logfile;
  std::mutex logfile_mx;

  Usage get_usage() const override { return GLOBAL; }

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

  void eval(snort::Packet *) override {}

  class EventHandler : public snort::DataHandler {
  public:
    EventHandler(NetworkMappingModule &module)
        : DataHandler("network_mapping"), module(module) {}
    NetworkMappingModule &module;

    void handle(snort::DataEvent &, snort::Flow *flow) override {
      if (flow) {
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
    IT_PROBE,
    PROTO_BIT__ALL, // PROTO_BIT__ANY_IP, // PROTO_BIT__ALL, PROTO_BIT__NONE, //
    nullptr,        // buffers
    nullptr,        // service
    nullptr,        // pinit
    nullptr,        // pterm
    nullptr,        // tinit
    nullptr,        // tterm
    [](Module *module) -> Inspector * {
      return new NetworkMappingInspector(
          dynamic_cast<NetworkMappingModule *>(module));
    },
    [](Inspector *p) { delete p; },
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi *snort_plugins[] = {&networkmap_api.base, nullptr};
