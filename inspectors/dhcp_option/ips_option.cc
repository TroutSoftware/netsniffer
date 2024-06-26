
#include <cstdint>

#include <framework/base_api.h>
#include <framework/cursor.h>
#include <framework/ips_option.h>
#include <framework/module.h>
#include <hash/hash_key_operations.h>
#include <protocols/packet.h>

#include "flow_data.h"
#include "ips_option.h"

namespace dhcp_option {
namespace {

static const char *s_name = "dhcp_option";
static const char *s_help = "Filters on values of DHCP options";

static const snort::Parameter module_params[] = {
    {"~", snort::Parameter::PT_INT, "1:254", "0",
     "Identifies specific DHCP option (1 to 254)"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

class Module : public snort::Module {

  uint8_t value = 0;

  Module() : snort::Module(s_name, s_help, module_params) {}

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {

    if (val.is("~")) {
      // Got value
      value = val.get_uint8();
      return true;
    }

    return false;
  }

  Usage get_usage() const override { return DETECT; }

public:
  static snort::Module *ctor() { return new Module(); }

  static void dtor(snort::Module *p) { delete p; }

  uint8_t getValue() { return value; }
};

class IpsOption : public snort::IpsOption {

  uint8_t value = 0;

  IpsOption(Module &module)
      : snort::IpsOption(s_name), value(module.getValue()) {}

  // Hash compare is used as a fast way two compare two instances of IpsOption
  uint32_t hash() const override {
    uint32_t a = snort::IpsOption::hash(), b = value, c = 0;

    mix(a, b, c);
    finalize(a, b, c);

    return c;
  }

  // If hashes match a real comparison check is made
  bool operator==(const snort::IpsOption &ips) const override {
    return snort::IpsOption::operator==(ips) &&
           dynamic_cast<const IpsOption &>(ips).value == value;
  }

  EvalStatus eval(Cursor &c, snort::Packet *p) override {

    if (!p->flow)
      return NO_MATCH;

    FlowData *flow_data =
        dynamic_cast<FlowData *>(p->flow->get_flow_data(FlowData::get_id()));

    if (!flow_data) {
      return NO_MATCH;
    }

    size_t offset, size;

    if (value == 0 || !flow_data->get(value, offset, size)) {
      // If we don't have the option or it is unset, then there isn't a match
      return NO_MATCH;
    }

    // Set cursor to point to the option of this data
    c.set(s_name, p->data + offset, size);

    return MATCH;
  }

  snort::CursorActionType get_cursor_type() const override {
    return snort::CAT_ADJUST;
  }

public:
  static snort::IpsOption *ctor(snort::Module *module, OptTreeNode *) {
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
                                  snort::OPT_TYPE_DETECTION,
                                  0,
                                  PROTO_BIT__TCP,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  IpsOption::ctor,
                                  IpsOption::dtor,
                                  nullptr};

} // namespace dhcp_option
