#include <iostream>

#include "framework/inspector.h"
#include "framework/module.h"
#include "protocols/packet.h"
#include "pub_sub/appid_event_ids.h"
#include "pub_sub/http_event_ids.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "sfip/sf_ip.h"

#include "test_packet/test_packet.rs.h"

using namespace snort;

// TODO(rdo) use this to parametrize the tests
static const Parameter nm_params[] = {
    {"cap", Parameter::PT_STRING, nullptr, nullptr,
     "PCAP file to read packets from"},
    {"other", Parameter::PT_INT, "0:max32", nullptr, ""},
    {nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr},
};

class TestModule : public Module {
public:
  TestModule()
      : Module("test_packet", "Tests the Rust wrapper around packets",
               nm_params) {}

  Usage get_usage() const override { return INSPECT; }

  bool begin(const char *name, int idx, SnortConfig *cfg) override {
    std::cout << "==> begin against " << name << std::endl;
    return true;
  }

  bool end(const char *name, int idx, SnortConfig *cfg) override {
    std::cout << "==> end against " << name << std::endl;
    return true;
  }

  bool set(const char *name, Value &val, SnortConfig *cfg) override {
    std::cout << "set against " << name << val.get_string() << " " << std::endl;
    return true;
  }
};

class TestInspector : public Inspector {
  TestModule *module;

  void eval(Packet *packet) override {
    assert(packet);
    eval_packet(*packet);
  }

public:
  TestInspector(TestModule *module) : module(module) {}
};

const InspectApi test_packetapi = {
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "test_packet",
        "Tests the Rust wrapper around packets",
        []() -> Module * { return new TestModule; },
        [](Module *m) { delete m; },
    },
    IT_PACKET,
    PROTO_BIT__ALL,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    [](Module *module) -> Inspector * {
      return new TestInspector((TestModule *)module);
    },
    [](Inspector *p) { delete p; },
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi *snort_plugins[] = {&test_packetapi.base, nullptr};
