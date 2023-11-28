// Copyright (c) Trout Software 2023

#include "framework/inspector.h"
#include "framework/module.h"
#include "protocols/packet.h"

using namespace snort;

static const char* s_name = "trafic_log";
static const char* s_help = "trafic_log logging network trafic";

class TrafficLogModule : public Module
{
public:
    TrafficLogModule() : Module(s_name, s_help) { }
};

class TrafficLogInspector : public Inspector
{
private:
    void eval(Packet*p) override {
        // This is the magic function that should be filled out
    }

};

const InspectApi reputation_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        []()->Module*{return new TrafficLogModule;},    // Module constructor
        [](Module* m){delete m;},                       // Module destructor
    },
    IT_PASSIVE,
    PROTO_BIT__ANY_IP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    [](Module*)->Inspector*{return new TrafficLogInspector();},  // Inspector constructor
    [](Inspector* p){delete p;},                    // Inspector destructor
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &reputation_api.base,    
    nullptr
};

