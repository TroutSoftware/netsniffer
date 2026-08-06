#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes
#include <framework/module.h>
#include <hash/hash_key_operations.h>
#include <protocols/packet.h>

// System includes
#include <map>
#include <string>

// Global includes

// Local includes
#include "flow_data.h"
#include "ips_option_mqtt_field.h"
#include "mqtt_protocol_defs.h"

// Debug includes
#include <iostream>

namespace mqtt_plugin {
namespace {

static const char *s_name = "mqtt_field";

static const char *s_help = "moves cursor to given field";

static const snort::Parameter module_params[] = {
    {"~", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Field requested"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

const PegInfo s_pegs[] = {
    {CountType::SUM, "invokations", "Number of times a paket was serached"},
    {CountType::SUM, "matches",
     "Number of times the field was found"},
    {CountType::END, nullptr, nullptr}};

// This must match the s_pegs[] array
THREAD_LOCAL struct PegCounts {
  PegCount invokations = 0;
  PegCount matches = 0;
} s_peg_counts;

// Compile time sanity check of number of entries in s_pegs and s_peg_counts
static_assert(
    (sizeof(s_pegs) / sizeof(PegInfo)) - 1 ==
        sizeof(PegCounts) / sizeof(PegCount),
    "Entries in s_pegs doesn't match number of entries in s_peg_counts");

using GetterFuncSignature = snort::IpsOption::EvalStatus(*)(Cursor &, PacketFlowData *);

snort::IpsOption::EvalStatus dummyGetter(Cursor &, PacketFlowData*) {
  return snort::IpsOption::NO_MATCH;
}

snort::IpsOption::EvalStatus client_id_getter(Cursor &c, PacketFlowData *flow_data) {
  if(flow_data->client_id.size()) {
    c.set("MQTT.ClientID", flow_data->client_id.data(), flow_data->client_id.size());
    return snort::IpsOption::MATCH;
  }

  // We found no match
  return snort::IpsOption::NO_MATCH;
}

snort::IpsOption::EvalStatus connect_will_topic_getter(Cursor &c, PacketFlowData *flow_data) {
  if (auto* p = std::get_if<ConnectMsg>(&(flow_data->cur_msg))) {
    auto val = p->will_topic;
    if (val) {
      c.set("MQTT.Connect.WillTopic", val->data(), val->size());
      return snort::IpsOption::MATCH;
    }
  }

  // We found no match
  return snort::IpsOption::NO_MATCH;
}

snort::IpsOption::EvalStatus connect_will_message_getter(Cursor &c, PacketFlowData *flow_data) {
  if (auto* p = std::get_if<ConnectMsg>(&(flow_data->cur_msg))) {
    auto val = p->will_message;
    if (val) {
      c.set("MQTT.Connect.WillMessage", val->data(), val->size());
      return snort::IpsOption::MATCH;
    }
  }

  // We found no match
  return snort::IpsOption::NO_MATCH;
}

snort::IpsOption::EvalStatus connect_user_name_getter(Cursor &c, PacketFlowData *flow_data) {
  if (auto* p = std::get_if<ConnectMsg>(&(flow_data->cur_msg))) {
    auto val = p->user_name;
    if (val) {
      c.set("MQTT.Connect.UserName", val->data(), val->size());
      return snort::IpsOption::MATCH;
    }
  }

  // We found no match
  return snort::IpsOption::NO_MATCH;
}

snort::IpsOption::EvalStatus connect_password_getter(Cursor &c, PacketFlowData *flow_data) {
  if (auto* p = std::get_if<ConnectMsg>(&(flow_data->cur_msg))) {
    auto val = p->password;
    if (val) {
      c.set("MQTT.Connect.PassWord", val->data(), val->size());
      return snort::IpsOption::MATCH;
    }
  }

  // We found no match
  return snort::IpsOption::NO_MATCH;
}

snort::IpsOption::EvalStatus connect_extra_getter(Cursor &c, PacketFlowData *flow_data) {
  if (auto* p = std::get_if<ConnectMsg>(&(flow_data->cur_msg))) {
    auto val = p->extra;
    if (val) {
      c.set("MQTT.Connect.Extra", val->data(), val->size());
      return snort::IpsOption::MATCH;
    }
  }

  // We found no match
  return snort::IpsOption::NO_MATCH;
}



namespace {
static const std::map<std::string, GetterFuncSignature> mqtt_field_map  {
  {"ClientID", client_id_getter},   // Valid for all messages

  // Valid for Connect message, fields will return NO_MATCH if not found in message
  // NOTE: messages can be present but empty and will retrun MATCH in that case
  {"Connect.WillTopic", connect_will_topic_getter},
  {"Connect.WillMessage", connect_will_message_getter},
  {"Connect.UserName", connect_user_name_getter},
  {"Connect.Password", connect_password_getter},
  {"Connect.Extra", connect_extra_getter},

};
} // namespace {


class Module : public snort::Module {


  GetterFuncSignature getterFunc = dummyGetter;

  Module() : snort::Module(s_name, s_help, module_params) {}

  bool begin(const char *, int, snort::SnortConfig *) override {
    getterFunc = dummyGetter;
    return true;
  }

  bool end(const char *, int, snort::SnortConfig *) override {
    return getterFunc != dummyGetter;
  }

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("~")) {
      auto field = mqtt_field_map.find(val.get_as_string());

      if (field == mqtt_field_map.end()) {
std::cerr << "MKRTEST: IPS option was not found: " << val.get_as_string() << std::endl;
        return false;
      }

      getterFunc = field->second;
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

  GetterFuncSignature get_getter() { return getterFunc; }
};

class IpsOption : public snort::IpsOption {

  GetterFuncSignature getterFunc;

  IpsOption(Module &module) : snort::IpsOption(s_name), getterFunc(module.get_getter()) {}

  // Hash compare is used as a fast way to compare two instances of IpsOption
  uint32_t hash() const override {
    static_assert(sizeof(getterFunc) <= 8);

    uint64_t p = static_cast<uint64_t>(reinterpret_cast<std::uintptr_t>(getterFunc));

    uint32_t a = static_cast<uint32_t>(p & 0xFFFF'FFFF);
    uint32_t b = static_cast<uint32_t>(p >> 32);
    uint32_t c = 0;

    mix(a,b,c);
    finalize(a,b,c);

    return c;
  }

  // If hashes match a real comparison check is made
  bool operator==(const snort::IpsOption &ips) const override {
    return getterFunc == dynamic_cast<const IpsOption &>(ips).getterFunc;
  }

  EvalStatus eval(Cursor &c, snort::Packet *p) override {
    assert(p);
    PacketFlowData *flow_data = PacketFlowData::get_from_flow(p->flow);
    return getterFunc(c, flow_data);
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
                                  PROTO_BIT__PDU,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  IpsOption::ctor,
                                  IpsOption::dtor,
                                  nullptr};

} // namespace mqtt_plugin
