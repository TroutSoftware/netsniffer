#include <iostream>

#include "framework/inspector.h"
#include "framework/module.h"
#include "protocols/packet.h"
#include "pub_sub/appid_event_ids.h"
#include "pub_sub/http_event_ids.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "sfip/sf_ip.h"

#include "network_mapping/lib.rs.h"
#include "rust.h"

using namespace snort;

static const Parameter nm_params[] = {
    {"cache_size", Parameter::PT_INT, "0:max32", "0", "set cache size"},
};

class NetworkMappingModule : public Module {
public:
  NetworkMappingModule()
      : Module("network_mapping",
               "Help map resources in the network based on their comms",
               nm_params) {}

  Usage get_usage() const override { return GLOBAL; }
};

class NetworkMappingInspector : public Inspector {
  NetworkMappingModule *module;

  void eval(Packet *packet) override {
    assert(packet);
    eval_packet(*packet);
  }

public:
  NetworkMappingInspector(NetworkMappingModule *module) : module(module) {}

  class EventHandler : public snort::DataHandler {
    const char *c;

  public:
    EventHandler(const char *c) : DataHandler("network_mapping"), c(c) {}

    void handle(snort::DataEvent &event, snort::Flow *flow) override {
      std::cout << "++ EventHandler::handle called(" << c << ")" << std::endl;
    }
  };

  bool configure(SnortConfig *sc) override {
    // sc->set_run_flags(RUN_FLAG__TRACK_ON_SYN);

    //    static void subscribe(const PubKey&, unsigned id, DataHandler*);
    //    static void subscribe_network(const PubKey&, unsigned id,
    //    DataHandler*); static void subscribe_global(const PubKey&, unsigned
    //    id, DataHandler*, SnortConfig&);

    DataBus::subscribe_network(
        appid_pub_key, AppIdEventIds::ANY_CHANGE,
        new EventHandler("appid_pub_key, AppIdEventIds::ANY_CHANGE"));
    DataBus::subscribe_network(
        http_pub_key, HttpEventIds::REQUEST_HEADER,
        new EventHandler("http_pub_key, HttpEventIds::REQUEST_HEADER"));
    DataBus::subscribe_network(
        http_pub_key, HttpEventIds::RESPONSE_HEADER,
        new EventHandler("http_pub_key, HttpEventIds::RESPONSE_HEADER"));
    DataBus::subscribe_network(
        http_pub_key, HttpEventIds::REQUEST_BODY,
        new EventHandler("http_pub_key, HttpEventIds::REQUEST_BODY"));

    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::DAQ_SOF_MSG,
        new EventHandler("IntrinsicEventIds::DAQ_SOF_MSG"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::DAQ_EOF_MSG,
        new EventHandler("IntrinsicEventIds::DAQ_EOF_MSG"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::DAQ_OTHER_MSG,
        new EventHandler("IntrinsicEventIds::DAQ_OTHER_MSG"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::ALT_PACKET,
        new EventHandler("IntrinsicEventIds::ALT_PACKET"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::PKT_WITHOUT_FLOW,
        new EventHandler("IntrinsicEventIds::PKT_WITHOUT_FLOW"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::DETAINED_PACKET,
        new EventHandler("IntrinsicEventIds::DETAINED_PACKET"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::FINALIZE_PACKET,
        new EventHandler("IntrinsicEventIds::FINALIZE_PACKET"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::RETRY_PACKET,
        new EventHandler("IntrinsicEventIds::RETRY_PACKET"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::THREAD_IDLE,
        new EventHandler("IntrinsicEventIds::THREAD_IDLE"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::THREAD_ROTATE,
        new EventHandler("IntrinsicEventIds::THREAD_ROTATE"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::SSL_SEARCH_ABANDONED,
        new EventHandler("IntrinsicEventIds::SSL_SEARCH_ABANDONED"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::OPPORTUNISTIC_TLS,
        new EventHandler("IntrinsicEventIds::OPPORTUNISTIC_TLS"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::FLOW_STATE_CHANGE,
        new EventHandler("IntrinsicEventIds::FLOW_STATE_CHANGE"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::FLOW_SERVICE_CHANGE,
        new EventHandler("IntrinsicEventIds::FLOW_SERVICE_CHANGE"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::SERVICE_INSPECTOR_CHANGE,
        new EventHandler("IntrinsicEventIds::SERVICE_INSPECTOR_CHANGE"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::FLOW_NO_SERVICE,
        new EventHandler("IntrinsicEventIds::FLOW_NO_SERVICE"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::FLOW_STATE_SETUP,
        new EventHandler("IntrinsicEventIds::FLOW_STATE_SETUP"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::FLOW_STATE_RELOADED,
        new EventHandler("IntrinsicEventIds::FLOW_STATE_RELOADED"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::FLOW_ASSISTANT_GADGET,
        new EventHandler("IntrinsicEventIds::FLOW_ASSISTANT_GADGET"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::EXPECT_HANDLE_FLOWS,
        new EventHandler("IntrinsicEventIds::EXPECT_HANDLE_FLOWS"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::EXPECT_EARLY_SESSION,
        new EventHandler("IntrinsicEventIds::EXPECT_EARLY_SESSION"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::DAQ_SOF_MSG,
        new EventHandler("IntrinsicEventIds::DAQ_SOF_MSG"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::FILE_VERDICT,
        new EventHandler("IntrinsicEventIds::FILE_VERDICT"));
    DataBus::subscribe_network(
        intrinsic_pub_key, IntrinsicEventIds::AUXILIARY_IP,
        new EventHandler("IntrinsicEventIds::AUXILIARY_IP"));

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
      return new NetworkMappingInspector((NetworkMappingModule *)module);
    },
    [](Inspector *p) { delete p; },
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi *snort_plugins[] = {&networkmap_api.base, nullptr};
