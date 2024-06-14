
#include <framework/base_api.h>
#include <framework/inspector.h>
#include <framework/module.h>
#include <protocols/packet.h>

#include "inspector.h"

namespace dhcp_option {
namespace {

static const char *s_name = "dhcp_option";
static const char *s_help = "Identifies and parses DHCP packages";
static const unsigned gid = 8000;      // Module wide GID
static const unsigned dhcp_sid = 1010; // Detected DHCP package
static const snort::Parameter module_params[] = {
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

class Module : public snort::Module {

  // const snort::PegInfo *get_pegs() const override { return s_pegs; }
  // snort::PegCount *get_counts() const override { return (snort::PegCount
  // *)&s_dhcp_stats; }
  unsigned get_gid() const override { return gid; }
  // const snort::RuleMap *get_rules() const override { return s_rules; }
  bool is_bindable() const override { return true; }

  Module() : snort::Module(s_name, s_help, module_params) {}

public:
  static snort::Module *ctor() { return new Module(); }

  static void dtor(snort::Module *p) { delete p; }
};

class Inspector : public snort::Inspector {

  Inspector(Module *) {}

  ~Inspector() {}

  void eval(snort::Packet *) override {}

  // bool configure(SnortConfig *) override;

public:
  static snort::Inspector *ctor(snort::Module *module) {
    return new Inspector(dynamic_cast<Module *>(module));
  }

  static void dtor(snort::Inspector *p) { delete p; }
};

} // namespace

const snort::InspectApi inspector = {
    {
        PT_INSPECTOR,
        sizeof(snort::InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        Module::ctor,
        Module::dtor,
    },

    snort::IT_PASSIVE,
    PROTO_BIT__ALL,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    Inspector::ctor,
    Inspector::dtor,
    nullptr, // ssn
    nullptr  // reset
};

} // namespace dhcp_option
