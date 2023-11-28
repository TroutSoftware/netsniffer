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
    TrafficLogModule() : Module((char*)getModuleName(), (char*)getModuleHelpText()) { }
};

class TrafficLogInspector : public Inspector
{
private:
    void eval(Packet*p) override {
        // This is the magic function that should be filled out
    }

};

class myStaticClass
{
public:
    myStaticClass()
    {
        std::cout << "------------------ Strange name: >" << getModuleName() << "<" << std::endl;
    }
} myStaticClass;

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

