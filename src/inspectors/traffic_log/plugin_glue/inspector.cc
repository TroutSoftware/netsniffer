// Copyright (c) Trout Software 2023

// Snort includes
#include "framework/inspector.h"
#include "framework/module.h"
#include "protocols/packet.h"
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
        snortEval(reinterpret_cast<SnortPacket>(packet));
    }
public:
    TrafficLogInspector(TrafficLogModule *module) : module(module) {
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
    IT_PROBE, 
    PROTO_BIT__ANY_IP, // PROTO_BIT__ALL, 
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

