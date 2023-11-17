//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// null_trace_logger.cc author Oleksandr Serhiienko <oserhiie@cisco.com>
//                      author Oleksii Shumeiko <oshumeik@cisco.com>

#include "framework/decode_data.h"  // for PROTO_BIT__NONE
#include "framework/inspector.h"
#include "framework/module.h"
#include "trace/trace_api.h"
#include "trace/trace_logger.h"

#include <iostream>

static const char* s_name = "mkr_inspector";
static const char* s_help = "mkr playground inspector logger";

using namespace snort;

extern "C" void rust_pkg(const uint32_t len, const uint8_t* pkt);
extern "C" void rust_payload(uint16_t size, const uint8_t *data);

//-------------------------------------------------------------------------
// logger
//-------------------------------------------------------------------------

class MyInspectorLogger : public TraceLogger
{
public:
    void log(const char*, const char*, uint8_t, const char*, const Packet*) override
    {    
    }
};

//-------------------------------------------------------------------------
// logger factory
//-------------------------------------------------------------------------

class MyInspectorLoggerFactory : public TraceLoggerFactory
{
public:
    MyInspectorLoggerFactory() = default;
    MyInspectorLoggerFactory(const MyInspectorLoggerFactory&) = delete;
    MyInspectorLoggerFactory& operator=(const MyInspectorLoggerFactory&) = delete;

    TraceLogger* instantiate() override
    {     
        return new MyInspectorLogger();
    }
};

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

class MyInspectorLoggerModule : public Module
{
public:
    MyInspectorLoggerModule() : Module(s_name, s_help) { }

    Usage get_usage() const override
    { return GLOBAL; }
};

//-------------------------------------------------------------------------
// inspector
//-------------------------------------------------------------------------

class MyInspectorLoggerInspector : public Inspector
{
public:
    void eval(Packet*p) override {
        rust_pkg(p->pktlen, p->pkt);
        rust_payload(p->dsize, p->data);
    }
    bool configure(SnortConfig* sc) override 
    //{ return TraceApi::override_logger_factory(sc, new MyInspectorLoggerFactory()); }
    {    
        return true;
    }

    bool likes(Packet*) override
    {
        std::cout << "Inspector presented with package" << std::endl;
        return true;
    }
};

//-------------------------------------------------------------------------
// API
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new MyInspectorLoggerModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Inspector* ntl_ctor(Module*)
{
    return new MyInspectorLoggerInspector;
}

static void ntl_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi ntl_api
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
        mod_ctor,
        mod_dtor
    },
    IT_PROBE, //IT_SERVICE, //IT_CONTROL, //IT_PACKET, //IT_PROBE, //IT_PASSIVE,
    PROTO_BIT__ALL, //PROTO_BIT__NONE,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit,
    nullptr, // tterm,
    ntl_ctor,
    ntl_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &ntl_api.base,
    nullptr
};

