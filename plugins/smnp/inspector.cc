
// Snort includes
#include <detection/detection_engine.h>
#include <framework/base_api.h>
#include <framework/counts.h>
#include <framework/inspector.h>
#include <framework/module.h>
// #include <main/snort_config.h>
#include <protocols/packet.h>

// System includes
// #include <cassert>
// #include <cstring>
// #include <memory>

// Local includes
#include "inspector.h"

// Debug includes

namespace smnp {
namespace {

static const char *s_name = "smnp";
static const char *s_help = "Dummy SMNP inspector, assigns the smnp type to "
                            "all pacakages it is presented";

static const snort::Parameter module_params[] = {
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

// Note: Snort pegs are not part of the snort namespace, this array must match
// the PegData struct
const PegInfo s_pegs[] = {
    {CountType::SUM, "packets_presented",
     "Number of packets presented to inspector"},
    {CountType::SUM, "services_detected",
     "Number of times the inspector detected the service"},
    {CountType::END, nullptr, nullptr}};

// This must match the s_pegs[] array
static THREAD_LOCAL struct PegCounts {
  PegCount packets_presented = 0;
  PegCount services_detected = 0;
} s_peg_counts;

// Compile time sanity check of number of entries in s_pegs and s_peg_counts
static_assert(
    (sizeof(s_pegs) / sizeof(PegInfo)) - 1 ==
        sizeof(PegCounts) / sizeof(PegCount),
    "Entries in s_pegs doesn't match number of entries in s_peg_counts");

class Module : public snort::Module {

  const PegInfo *get_pegs() const override { return s_pegs; }
  PegCount *get_counts() const override {
    return reinterpret_cast<PegCount *>(&s_peg_counts);
  }

  bool is_bindable() const override { return true; }

  // Snort seems to complain if usage type isn't INSPECT when type is SERVICE
  Usage get_usage() const override { return INSPECT; }

  Module() : snort::Module(s_name, s_help, module_params) {}

public:
  static snort::Module *ctor() { return new Module(); }

  static void dtor(snort::Module *p) { delete p; }
};

class Inspector : public snort::Inspector {

  Module &module;

  Inspector(Module &module) : module(module) {}

  ~Inspector() {}

  void eval(snort::Packet *p) override {
    s_peg_counts.packets_presented++;
    if (p->flow && p->flow->service != s_name) {
      s_peg_counts.services_detected++;
      p->flow->set_service(p, s_name);
    }
  }

public:
  static snort::Inspector *ctor(snort::Module *module) {
    return new Inspector(*dynamic_cast<Module *>(module));
  }

  static void dtor(snort::Inspector *p) { delete p; }
};

} // namespace

const snort::InspectApi inspect_api = {
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
    snort::IT_SERVICE,
    PROTO_BIT__ALL,
    nullptr, // buffers
    s_name,  // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    Inspector::ctor,
    Inspector::dtor,
    nullptr, // ssn
    nullptr  // reset
};

} // namespace smnp
