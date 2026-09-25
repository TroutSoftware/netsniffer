#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes
#include <framework/module.h>
#include <log/messages.h>
#include <protocols/packet.h>

// System includes

// Global includes
#include "../includes/lioli_path.h"
#include "../wrappers/pegs_peg_list.h"

// Local includes
#include "common.h"
#include "ips_lioli_clear.h"

// Debug includes

namespace ips_lioli_clear {
namespace {

static const char *s_name = "lioli_clear";

static const char *s_help = "clears all previous lioli content on flow";

static const snort::Parameter module_params[] = {
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

using namespace trout::templates;

// clang-format off
using Pegs = PegList<
  Peg<Name<"clear_events">, Type<PegType::SUM>, HelpText<"How many times clear was reached in a rule">>,
  Peg<Name<"did_clear">,    Type<PegType::SUM>, HelpText<"How many times data was purged">>,
  Peg<Name<"no_flow">,      Type<PegType::SUM>, HelpText<"Packets without flows">>
>;
// clang-format on

class Module : public snort::Module {

  Module() : snort::Module(s_name, s_help, module_params) {}

  Usage get_usage() const override { return CONTEXT; }

  const PegInfo *get_pegs() const override {
    return Pegs::generate_snort_peg_info_def();
  }

  PegCount *get_counts() const override {
    return Pegs::generate_snort_peg_count_def();
  }

public:
  static snort::Module *ctor() { return new Module(); }

  static void dtor(snort::Module *p) { delete p; }
};

class IpsOption : public snort::IpsOption {

  IpsOption(Module &) : snort::IpsOption(s_name) {}

  // We always do the same thing
  uint32_t hash() const override { return 0; }

  // If hashes match a real comparison check is made
  bool operator==(const snort::IpsOption &) const override { return true; }

  EvalStatus eval(Cursor &, snort::Packet *p) override {
    Pegs::get<"clear_events">().inc();

    if (!p->flow) {
      Pegs::get<"no_flow">().inc();
      return MATCH;
    }

    alert_lioli::FlowData *flow_data =
        alert_lioli::FlowData::get_from_flow(p->flow);

    if (!flow_data->empty()) {
      Pegs::get<"did_clear">().inc();
    }

    flow_data->clear();

    return MATCH;
  }

  snort::CursorActionType get_cursor_type() const override {
    return snort::CAT_NONE;
  }

public:
  static snort::IpsOption *ctor(snort::Module *module, IpsInfo &) {
    assert(module);
    return new IpsOption(*dynamic_cast<Module *>(module));
  }

  static void dtor(snort::IpsOption *p) { delete p; }
};

} // namespace

const snort::IpsApi ips_option = {{
                                      PT_IPS_OPTION,
                                      sizeof(snort::IpsApi),
                                      IPSAPI_VERSION,
                                      0,
                                      API_RESERVED,
                                      API_OPTIONS,
                                      s_name,
                                      s_help,
                                      Module::ctor,
                                      Module::dtor,
                                  },
                                  snort::OPT_TYPE_LOGGING,
                                  0,
                                  PROTO_BIT__TCP,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  IpsOption::ctor,
                                  IpsOption::dtor,
                                  nullptr};

} // namespace ips_lioli_clear
