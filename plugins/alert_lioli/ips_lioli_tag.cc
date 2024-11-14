
// Snort includes
#include <framework/module.h>
#include <hash/hash_key_operations.h>
#include <log/messages.h>
#include <protocols/packet.h>

// System includes
#include <cassert>
#include <string>

// Local includes
#include "flow_data.h"
#include "ips_lioli_tag.h"
#include "lioli_path.h"

// Debug includes

namespace ips_lioli_tag {
namespace {

static const char *s_name = "lioli_tag_WIP";

static const char *s_help = "generates lioli tag node from parameter";

static const snort::Parameter module_params[] = {
    {"~", snort::Parameter::PT_STRING, nullptr, nullptr,
     "tag that should be added"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

class Module : public snort::Module {

  LioLi::Path tag;

  Module() : snort::Module(s_name, s_help, module_params) {}

  bool begin(const char *, int, snort::SnortConfig *) override {
    tag = std::move(LioLi::Path());
    return true;
  }

  bool end(const char *, int, snort::SnortConfig *) override { return true; }

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {

    if (val.is("~")) {
      auto arg = val.get_as_string();

      if (arg.length() >= 2 && arg.starts_with('"') && arg.ends_with('"')) {
        arg = arg.substr(1, arg.length() - 2);
      }

      auto split_at = arg.find_first_of(':');

      if (std::string::npos == split_at || 0 == split_at) {
        tag << std::move(LioLi::Tree("tag") << arg);
      } else {
        auto key = arg.substr(0, split_at);
        auto value = arg.substr(split_at + 1);

        if (!LioLi::Path::is_valid_path_name(key)) {
          snort::ErrorMessage("ERROR: %s is not a valid LioLi path\n",
                              key.c_str());
          return false;
        }
        tag << std::move(LioLi::Path(key) << value);
      }

      return true;
    }

    // fail if we didn't get something valid
    return false;
  }

  Usage get_usage() const override { return DETECT; }

public:
  static snort::Module *ctor() { return new Module(); }

  static void dtor(snort::Module *p) { delete p; }

  LioLi::Path &get_tag() { return tag; }
};

class IpsOption : public snort::IpsOption {

  LioLi::Path tag;

  IpsOption(Module &module) : snort::IpsOption(s_name), tag(module.get_tag()) {}

  // Hash compare is used as a fast way to compare two instances of IpsOption
  uint32_t hash() const override {
    uint32_t a = snort::IpsOption::hash(), b = tag.hash(), c = 0;

    mix(a, b, c);
    finalize(a, b, c);

    return c;
  }

  // If hashes match a real comparison check is made
  bool operator==(const snort::IpsOption &ips) const override {
    return snort::IpsOption::operator==(ips) &&
           (dynamic_cast<const IpsOption &>(ips).tag == tag);
  }

  EvalStatus eval(Cursor &, snort::Packet *p) override {
    if (!p->flow) {
      return NO_MATCH;
    }

    alert_lioli::FlowData *flow_data =
        alert_lioli::FlowData::get_from_flow(p->flow);

    *flow_data << tag;

    return MATCH;
  }

  snort::CursorActionType get_cursor_type() const override {
    return snort::CAT_ADJUST;
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
                                  PROTO_BIT__TCP,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  IpsOption::ctor,
                                  IpsOption::dtor,
                                  nullptr};

} // namespace ips_lioli_tag
