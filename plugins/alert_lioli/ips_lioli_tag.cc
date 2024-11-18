
// Snort includes
#include <framework/module.h>
#include <hash/hash_key_operations.h>
#include <log/messages.h>
#include <protocols/packet.h>

// System includes
#include <algorithm>
#include <cassert>
#include <regex>
#include <string>

// Local includes
#include "flow_data.h"
#include "ips_lioli_tag.h"
#include "lioli_path.h"

// Debug includes

namespace ips_lioli_tag {
namespace {

static const char *s_name = "lioli_tag";

static const char *s_help = "generates lioli tag node from parameter";

static const snort::Parameter module_params[] = {
    {"~", snort::Parameter::PT_STRING, nullptr, nullptr,
     "tag that should be added"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

class Module : public snort::Module {

  LioLi::Path tag;
  bool tag_valid = false;

  Module() : snort::Module(s_name, s_help, module_params) {}

  bool begin(const char *, int, snort::SnortConfig *) override {
    tag = std::move(LioLi::Path());
    tag_valid = false;
    return true;
  }

  bool end(const char *, int, snort::SnortConfig *) override {
    return tag_valid;
  }

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("~")) {
      auto arg = val.get_as_string();

      const static std::regex regex("(" + LioLi::Path::regex_path_name() +
                                        ")\\s\"([^\"]+)\"",
                                    std::regex::optimize);

      std::smatch sm;

      if (std::regex_match(arg, sm, regex)) {
        // We need to adjust for the number of parenthesis found in
        // regex_path_name() (note, this is done compile time)
        constexpr int parenthesis_count =
            std::ranges::count(LioLi::Path::regex_path_name(), '(');
        tag << (LioLi::Path(sm[1]) << sm[2 + parenthesis_count]);
        tag_valid = true;
        return true;
      }
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
