#include <framework/cursor.h>
#include <framework/module.h>
#include <hash/hash_key_operations.h>
#include <protocols/packet.h>

#include "flow_data.h"
#include "ips_lioli_bind.h"

#include <iostream>

namespace ips_lioli_bind {
namespace {

static const char *s_name = "lioli_bind";

static const char *s_help = "generates lioli node from current cursor position";

static const snort::Parameter module_params[] = {
    {"~", snort::Parameter::PT_STRING, nullptr, nullptr, "name of lioli node"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

class Module : public snort::Module {

  uint8_t value = 0;
  std::string node_name;

  Module() : snort::Module(s_name, s_help, module_params) {}

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {

    if (val.is("~")) {
      node_name = val.get_as_string();

      std::cout << "Exp-ips: Got node_name:" << node_name << std::endl;

      return true;
    }

    // fail if we didn't get something valid
    return false;
  }

  Usage get_usage() const override { return DETECT; }

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
    std::cout << "exp-ips: Eval called" << std::endl;
    if (!p->flow) {
      std::cout << "exp-ips: No flow" << std::endl;
      return NO_MATCH;
    }

    NetFlow::FlowData *flow_data = dynamic_cast<NetFlow::FlowData *>(
        p->flow->get_flow_data(NetFlow::FlowData::get_id()));

    if (!flow_data) {
      std::cout << "exp-ips: No flow-data" << std::endl;
      flow_data = new NetFlow::FlowData();
      p->flow->set_flow_data(flow_data);
    }
    /*
        const uint8_t* start() const
        { return buf + current_pos; }

        unsigned length() const
        { return buf_size - current_pos; }
    */
    const uint8_t *startpos = c.start();
    unsigned length = c.length();

    std::string content((char *)startpos, length);

    flow_data->lioli += node_name + ":" + content + ";";

    std::cout << "exp-ips: lioli is now: " << flow_data->lioli << std::endl;

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

} // namespace ips_lioli_bind
