
#include <framework/base_api.h>
#include <framework/ips_option.h>
#include <framework/module.h>
#include <hash/hash_key_operations.h>
#include <protocols/packet.h>

#include "ips_option.h"

namespace dhcp_option {
namespace {

static const char *s_name = "dhcp_option";
static const char *s_help = "Filters on values of DHCP options";

class Module : public snort::Module {

  Module() : snort::Module(s_name, s_help) {}

  //    ProfileStats* get_profile() const override
  //    { return &modbus_data_prof; }

  Usage get_usage() const override { return DETECT; }

public:
  static snort::Module *ctor() { return new Module(); }

  static void dtor(snort::Module *p) { delete p; }
};

class IpsOption : public snort::IpsOption {

  IpsOption() : snort::IpsOption(s_name) {}

  uint32_t hash() const override {
    uint32_t a = snort::IpsOption::hash(), b = 0, c = 0;

    mix(a, b, c);
    finalize(a, b, c);

    return c;
  }

  bool operator==(const snort::IpsOption &ips) const override {
    return snort::IpsOption::operator==(ips);
  }

  EvalStatus eval(Cursor &, snort::Packet *) override {

    /*
        RuleProfile profile(modbus_data_prof);

        if ( !p->flow )
            return NO_MATCH;

        if ( !p->is_full_pdu() )
            return NO_MATCH;

        if ( p->dsize < MODBUS_MIN_LEN )
            return NO_MATCH;

        c.set(s_name, p->data + MODBUS_MIN_LEN, p->dsize - MODBUS_MIN_LEN);
    */
    return MATCH;
  }

  snort::CursorActionType get_cursor_type() const override {
    return snort::CAT_SET_FAST_PATTERN;
  }

public:
  static snort::IpsOption *ctor(snort::Module *, OptTreeNode *) {
    return new IpsOption;
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
