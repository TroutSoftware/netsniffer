
// Snort includes
#include <framework/cursor.h>
#include <framework/module.h>
#include <hash/hash_key_operations.h>
#include <log/messages.h>
#include <protocols/packet.h>

// System includes
#include <cassert>
#include <string>

// Local includes
#include "flow_data.h"
#include "ips_lioli_bind.h"

// Global includes
#include "lioli_path.h"

namespace ips_lioli_bind {
namespace {

static const char *s_name = "lioli_bind";

static const char *s_help = "generates lioli node from current cursor position";

static const snort::Parameter module_params[] = {
    {"~", snort::Parameter::PT_STRING, nullptr, nullptr, "name of lioli node"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

const PegInfo s_pegs[] = {
    {CountType::SUM, "binds",
     "Number of times something was bounded to a package"},
    {CountType::SUM, "no_flows",
     "Number of times something couldn't be bound as there was no flow"},
    {CountType::SUM, "config_pass", "Count of config file parses that passed"},
    {CountType::END, nullptr, nullptr}};

// This must match the s_pegs[] array
THREAD_LOCAL struct PegCounts {
  PegCount binds = 0;
  PegCount no_flow = 0;
  PegCount config_pass = 0;
} s_peg_counts;

// Compile time sanity check of number of entries in s_pegs and s_peg_counts
static_assert(
    (sizeof(s_pegs) / sizeof(PegInfo)) - 1 ==
        sizeof(PegCounts) / sizeof(PegCount),
    "Entries in s_pegs doesn't match number of entries in s_peg_counts");

class Module : public snort::Module {
  std::string node_name;

  Module() : snort::Module(s_name, s_help, module_params) {}

  bool begin(const char *, int, snort::SnortConfig *) override {
    node_name.clear();
    return true;
  }

  bool end(const char *, int, snort::SnortConfig *) override { return true; }

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("~")) {
      node_name = val.get_as_string();

      if (!LioLi::Path::is_valid_path_name(node_name)) {
        snort::ErrorMessage("ERROR: %s is not a valid LioLi path\n",
                            node_name.c_str());
        return false;
      }

      s_peg_counts.config_pass++;
      return true;
    }

    // fail if we didn't get something valid
    return false;
  }

  Usage get_usage() const override { return DETECT; }

  const PegInfo *get_pegs() const override { return s_pegs; }

  PegCount *get_counts() const override {
    return reinterpret_cast<PegCount *>(&s_peg_counts);
  }

public:
  static snort::Module *ctor() { return new Module(); }

  static void dtor(snort::Module *p) { delete p; }

  std::string get_node_name() { return node_name; }
};

class IpsOption : public snort::IpsOption {

  std::string node_name;

  IpsOption(Module &module)
      : snort::IpsOption(s_name), node_name(module.get_node_name()) {}

  // Hash compare is used as a fast way to compare two instances of IpsOption
  uint32_t hash() const override {
    uint32_t a = snort::IpsOption::hash(), b = node_name.length(), c = 0;

    mix(a, b, c);
    finalize(a, b, c);

    return c;
  }

  // If hashes match a real comparison check is made
  bool operator==(const snort::IpsOption &ips) const override {
    return snort::IpsOption::operator==(ips) &&
           dynamic_cast<const IpsOption &>(ips).node_name.compare(node_name) ==
               0;
  }

  EvalStatus eval(Cursor &c, snort::Packet *p) override {
    if (!p->flow) {
      s_peg_counts.no_flow++;
      return NO_MATCH;
    }

    alert_lioli::FlowData *flow_data =
        alert_lioli::FlowData::get_from_flow(p->flow);

    const uint8_t *startpos = c.start();
    unsigned length = c.length();

    std::string content((char *)startpos, length);

    *flow_data << std::move(LioLi::Path(node_name) << content);

    s_peg_counts.binds++;

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

} // namespace ips_lioli_bind
