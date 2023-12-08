// Copyright (c) Trout Software 2023

// Snort includes
#include "framework/inspector.h"
#include "framework/module.h"
#include "protocols/packet.h"
#include "pub_sub/appid_event_ids.h"
#include "pub_sub/http_event_ids.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "sfip/sf_ip.h"


// Local includes
#include "rustlink.h"

// System includes
#include <iostream>

using namespace snort;

class TrafficLogModule : public Module
{
public:
    TrafficLogModule() : Module((char*)getModuleName(), (char*)getModuleHelpText()) {
        //std::cout << "**TrafficLogModule instantiated" << std::endl;
    }

    Usage get_usage() const override
    {
        return GLOBAL; //INSPECT;
    }
};

class TrafficLogInspector : public Inspector
{
    TrafficLogModule *module;

    void eval(Packet*packet) override {
        assert(packet);
//std::cout << "** sp: " << packet->ptrs.sp << std::endl;
//std::cout << "** dp: " << packet->ptrs.dp << std::endl;
std::cout << "** get_type(): " << packet->get_type() << std::endl;
std::cout << "** get_pseudo_type(): " << packet->get_pseudo_type() << std::endl;
if(packet->flow == 0) std::cout << "** packet->flow is null" << std::endl;
if(packet->flow != 0 && packet->flow->service == 0) std::cout << "** packet->flow->service is null" << std::endl;
if(packet->flow && packet->flow->service) {
    std::cout << "** flow.service: " << packet->flow->service << std::endl;
}

        snortEval(reinterpret_cast<SnortPacket>(packet));
    }
public:
    TrafficLogInspector(TrafficLogModule *module) : module(module) {
    }

    class EventHandler : public snort::DataHandler
    {
        const char *c;
    public:
        EventHandler(const char *c) : DataHandler((char*)getModuleName()), c(c) {}

        void handle(snort::DataEvent& event, snort::Flow* flow) override {
            std::cout << "++ EventHandler::handle called(" << c << ")" << std::endl;
        }
    };


    bool configure(SnortConfig* sc) override
    {
        std::cout << "++ configure being called" << std::endl;
        //sc->set_run_flags(RUN_FLAG__TRACK_ON_SYN);

//    static void subscribe(const PubKey&, unsigned id, DataHandler*);
//    static void subscribe_network(const PubKey&, unsigned id, DataHandler*);
//    static void subscribe_global(const PubKey&, unsigned id, DataHandler*, SnortConfig&);


        DataBus::subscribe_network(appid_pub_key, AppIdEventIds::ANY_CHANGE, new EventHandler("appid_pub_key, AppIdEventIds::ANY_CHANGE"));
        DataBus::subscribe_network(http_pub_key, HttpEventIds::REQUEST_HEADER, new EventHandler("http_pub_key, HttpEventIds::REQUEST_HEADER"));
        DataBus::subscribe_network(http_pub_key, HttpEventIds::RESPONSE_HEADER, new EventHandler("http_pub_key, HttpEventIds::RESPONSE_HEADER"));
        DataBus::subscribe_network(http_pub_key, HttpEventIds::REQUEST_BODY, new EventHandler("http_pub_key, HttpEventIds::REQUEST_BODY"));

        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::DAQ_SOF_MSG, new EventHandler("IntrinsicEventIds::DAQ_SOF_MSG"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::DAQ_EOF_MSG, new EventHandler("IntrinsicEventIds::DAQ_EOF_MSG"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::DAQ_OTHER_MSG, new EventHandler("IntrinsicEventIds::DAQ_OTHER_MSG"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::ALT_PACKET, new EventHandler("IntrinsicEventIds::ALT_PACKET"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::PKT_WITHOUT_FLOW, new EventHandler("IntrinsicEventIds::PKT_WITHOUT_FLOW"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::DETAINED_PACKET, new EventHandler("IntrinsicEventIds::DETAINED_PACKET"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::FINALIZE_PACKET, new EventHandler("IntrinsicEventIds::FINALIZE_PACKET"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::RETRY_PACKET, new EventHandler("IntrinsicEventIds::RETRY_PACKET"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::THREAD_IDLE, new EventHandler("IntrinsicEventIds::THREAD_IDLE"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::THREAD_ROTATE, new EventHandler("IntrinsicEventIds::THREAD_ROTATE"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::SSL_SEARCH_ABANDONED, new EventHandler("IntrinsicEventIds::SSL_SEARCH_ABANDONED"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::OPPORTUNISTIC_TLS, new EventHandler("IntrinsicEventIds::OPPORTUNISTIC_TLS"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::FLOW_STATE_CHANGE, new EventHandler("IntrinsicEventIds::FLOW_STATE_CHANGE"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::FLOW_SERVICE_CHANGE, new EventHandler("IntrinsicEventIds::FLOW_SERVICE_CHANGE"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::SERVICE_INSPECTOR_CHANGE, new EventHandler("IntrinsicEventIds::SERVICE_INSPECTOR_CHANGE"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::FLOW_NO_SERVICE, new EventHandler("IntrinsicEventIds::FLOW_NO_SERVICE"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::FLOW_STATE_SETUP, new EventHandler("IntrinsicEventIds::FLOW_STATE_SETUP"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::FLOW_STATE_RELOADED, new EventHandler("IntrinsicEventIds::FLOW_STATE_RELOADED"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::FLOW_ASSISTANT_GADGET, new EventHandler("IntrinsicEventIds::FLOW_ASSISTANT_GADGET"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::EXPECT_HANDLE_FLOWS, new EventHandler("IntrinsicEventIds::EXPECT_HANDLE_FLOWS"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::EXPECT_EARLY_SESSION, new EventHandler("IntrinsicEventIds::EXPECT_EARLY_SESSION"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::DAQ_SOF_MSG, new EventHandler("IntrinsicEventIds::DAQ_SOF_MSG"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::FILE_VERDICT, new EventHandler("IntrinsicEventIds::FILE_VERDICT"));
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::AUXILIARY_IP, new EventHandler("IntrinsicEventIds::AUXILIARY_IP"));

        return true;
    }
};

/// Functions linking to RUST ///
const uint8_t *getType(SnortPacket packet) {
    assert(packet);
    const char *type = reinterpret_cast<Packet*>(const_cast<void*>(packet))->get_type();

    return reinterpret_cast<const uint8_t*>(type);
}

bool hasIp(SnortPacket packet) {
    assert(packet);

    return reinterpret_cast<Packet*>(const_cast<void*>(packet))->has_ip();
}


uintptr_t getMaxIpLen() {
    return INET6_ADDRSTRLEN;
}

void getSrcIp(SnortPacket packet, uint8_t *srcData, uintptr_t srcLen) {
    assert(packet);
    assert(srcLen >= INET6_ADDRSTRLEN);

    auto srcIp = reinterpret_cast<Packet*>(const_cast<void*>(packet))->ptrs.ip_api.get_src();

    sfip_ntop(srcIp, reinterpret_cast<char*>(srcData), srcLen);
}


void getDstIp(SnortPacket packet, uint8_t *dstData, uintptr_t dstLen) {
    assert(packet);
    assert(dstLen >= INET6_ADDRSTRLEN);

    auto dstIp = reinterpret_cast<Packet*>(const_cast<void*>(packet))->ptrs.ip_api.get_dst();

    sfip_ntop(dstIp, reinterpret_cast<char*>(dstData), dstLen);
}

/////////////////////////////////



const InspectApi reputation_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        (const char*)getModuleName(),
        (const char*)getModuleHelpText(),
        []()->Module*{return new TrafficLogModule;},    // Module constructor
        [](Module* m){delete m;},                       // Module destructor
    },
    IT_PROBE, //IT_PASSIVE,
    PROTO_BIT__ALL, //PROTO_BIT__ANY_IP, // PROTO_BIT__ALL, PROTO_BIT__NONE, //
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    [](Module*module)->Inspector*{return new TrafficLogInspector((TrafficLogModule*)module);},  // Inspector constructor
    [](Inspector* p){delete p;},                    // Inspector destructor
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &reputation_api.base,
    nullptr
};

