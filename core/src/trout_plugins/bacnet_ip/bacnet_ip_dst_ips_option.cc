#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes
#include <framework/module.h>
//#include <framework/range.h>
//#include <hash/hash_key_operations.h>
//#include <log/messages.h>
#include <protocols/packet.h>

// System includes

// Global includes
#include <trout_plugins/wrappers/pegs_peg_list.h>

// Local includes
#include "bacnet_ip_defs.h"
#include "bacnet_ip_dst_options.h"

// Debug includes

namespace bacnet_ip {
namespace {

using Hash = uint32_t;

// clang-format off
using Pegs = PegList<
  Peg<Name<"packages_tested">,            Type<PegType::SUM>, HelpText<"The number of network packages that passed through the bacnet_ip_dst ips option">>,
>;
// clang-format on

// clang-format off
using namespace trout::templates;
class Module : public trout::templates::Module<
                   Pegs,                   
                   Name<"bacnet_ip_dst">,
                   HelpText<"Moves cursor to address field, first 16-byte (network byte order) is the network, next byte is the address length, if length is 0 it's a broadcast, remainder of the buffer is the address (\"length\" bytes)">> {
  // clang-format on

  Usage get_usage() const override { return DETECT; }

public:
  static snort::Module *ctor() { return new Module(); }

  static void dtor(snort::Module *p) { delete p; }

  std::shared_ptr<Settings> get_settings() { return settings; }
};

class IpsOption : public snort::IpsOption {
  std::shared_ptr<Settings> settings;

  IpsOption(Module &module)
      : snort::IpsOption(s_name), settings(module.get_settings()) {}

  // Hash compare is used as a fast way to compare two instances of IpsOption
  uint32_t hash() const override { return 0 }

  // If hashes match a real comparison check is made
  bool operator==(const snort::IpsOption &/*ips*/) const override {
    // This ips option doesn't take any arguments, so two instances are always equal
    return true;
  }

  EvalStatus eval(Cursor &c, snort::Packet *p) override {
    assert(p);

    Pegs::get<"packages_tested">().inc();

    // Bacnet is UDP
    if (!p->is_udp()) {
      return snort::IpsOption::NO_MATCH;
    }

    
    // Byte 0: version, must be 1
    // Byte 1: 
/*
    EvalStatus result = settings->getter_func(c, *flow_data);

    // Check if a filter should be applied
    if (result == snort::IpsOption::MATCH && settings->match_list.size() != 0) {
      // We assume no match, until proven otherwise
      result = snort::IpsOption::NO_MATCH;
      for (auto &ele : settings->match_list) {
        assert(ele.matcher);
        bool matches = ele.matcher->match(c, *flow_data);

        if (ele.invert_result) {
          matches = !matches;
        }

        if (matches) {
          result = snort::IpsOption::MATCH;
          break;
        }
      }
    }

    if (settings->invert_result) {
      if (result == snort::IpsOption::MATCH) {
        return snort::IpsOption::NO_MATCH;
      }
      if (result == snort::IpsOption::NO_MATCH) {
        return snort::IpsOption::MATCH;
      }
    }
    return result;
*/    
  }

  snort::CursorActionType get_cursor_type() const override {
    return snort::CAT_SET_OTHER;
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
                                  snort::OPT_TYPE_DETECTION,
                                  0,
                                  PROTO_BIT__PDU,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  IpsOption::ctor,
                                  IpsOption::dtor,
                                  nullptr};

} // namespace bacnet_ip
