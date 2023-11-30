// Copyright (c) Trout Software 2023

#include "framework/inspector.h"
#include "framework/module.h"
#include "protocols/packet.h"
#include "rustlink.h"

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
        //std::cout << "**Calling Rust from C" << std::endl;
        snortEval(reinterpret_cast<SnortPacket>(packet));
    }
public:
    TrafficLogInspector(TrafficLogModule *module) : module(module) {
        //std::cout << "**TrafficLogInspector instantiated" << std::endl;
    }
};

const uint8_t *getType(const void *packet) {
    const char *type = reinterpret_cast<Packet*>(const_cast<void*>(packet))->get_type();
    //std::cout << "** C++ snort says type is: " << type << std::endl;
    return reinterpret_cast<const uint8_t*>(type);
}

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

