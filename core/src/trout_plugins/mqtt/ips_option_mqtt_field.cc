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

snort::IpsOption::EvalStatus dummy_getter(Cursor &, PacketFlowData*) {
  return snort::IpsOption::NO_MATCH;
}

snort::IpsOption::EvalStatus client_id_getter(Cursor &c, PacketFlowData *flow_data) {
  if (flow_data->client_id.size()) {
std::cerr << "MKRTEST: ClintID: " << flow_data->client_id[0] << std::endl;
    c.set("MQTT.ClientID", flow_data->client_id.data(), flow_data->client_id.size());
    return snort::IpsOption::MATCH;
  }
std::cerr << "MKRTEST: No client id" << std::endl;
  // We found no match
  return snort::IpsOption::NO_MATCH;
}

snort::IpsOption::EvalStatus protocol_level_getter(Cursor &c, PacketFlowData *flow_data) {
  if (flow_data->protocol_level != 0) {
    c.set("MQTT.ProtocolLevel", &flow_data->protocol_level, sizeof(flow_data->protocol_level));
    return snort::IpsOption::MATCH;
  }

  // We found no match
  return snort::IpsOption::NO_MATCH;
}

snort::IpsOption::EvalStatus msg_connect(Cursor &, PacketFlowData *flow_data) {
  if (std::get_if<ConnectMsg>(&(flow_data->cur_msg))) {
    return snort::IpsOption::MATCH;
  }

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

snort::IpsOption::EvalStatus connect_flag_will_retain(Cursor &, PacketFlowData *flow_data) {
  auto* p = std::get_if<ConnectMsg>(&(flow_data->cur_msg));

  if (p && p->will_retain) {
    return snort::IpsOption::MATCH;
  }

  // We found no match
  return snort::IpsOption::NO_MATCH;
}

snort::IpsOption::EvalStatus connect_flag_clean_session(Cursor &, PacketFlowData *flow_data) {
  auto* p = std::get_if<ConnectMsg>(&(flow_data->cur_msg));

std::cerr << "MKRTEST: Got a clean_session check" << std::endl;

  if (p && p->clean_session) {
std::cerr << "MKRTEST: Got a clean_session MATCH" << std::endl;
    return snort::IpsOption::MATCH;
  }

std::cerr << "MKRTEST: Didn't get a clean_session MATCH" << std::endl;
  // We found no match
  return snort::IpsOption::NO_MATCH;
}

namespace {
static const std::map<std::string, GetterFuncSignature> mqtt_field_map  {

  {"Flow.ClientID", client_id_getter},   // Valid for all messages
  {"Flow.ProtocolLevel", protocol_level_getter},

  // Checks message
  {"Msg.Connect", msg_connect},

  // Valid for Connect message, fields will return NO_MATCH if not found in message
  // NOTE: messages can be present but empty and will return MATCH in that case
  {"Connect.WillTopic", connect_will_topic_getter},
  {"Connect.WillMessage", connect_will_message_getter},
  {"Connect.UserName", connect_user_name_getter},
  {"Connect.Password", connect_password_getter},
  {"Connect.Extra", connect_extra_getter},
  // Connect flags will return MATCH if found, NO_MATCH if not found, flags will not move cursor
  {"Connect.Flag.WillRetain", connect_flag_will_retain},
  {"Connect.Flag.CleanSession", connect_flag_clean_session},

  // TODO: Add:  uint8_t will_qos = 0;

};
} // namespace {


class Module : public snort::Module {


  GetterFuncSignature getter_func = dummy_getter;
  bool invert_result = false;

  Module() : snort::Module(s_name, s_help, module_params) {}

  bool begin(const char *, int, snort::SnortConfig *) override {
    getter_func = dummy_getter;
    invert_result = false;
    return true;
  }

  bool end(const char *, int, snort::SnortConfig *) override {
    return getter_func != dummy_getter;
  }

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("~")) {
      std::string s = val.get_as_string();

      // Check if results should be negated
      if (s.size()>=1 && s[0] == '!') {
std::cerr << "MKRTEST: Detected a not in " << s << std::endl;
        invert_result = true;
        s.erase(0, 1);
      } else {
std::cerr << "MKRTEST: Did NOT detected a not in " << s << std::endl;
      }


      auto field = mqtt_field_map.find(s);

      if (field == mqtt_field_map.end()) {
        return false;
      }

      getter_func = field->second;
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

  GetterFuncSignature get_getter() { return getter_func; }
  bool get_invert_result() { return invert_result; }
};

class IpsOption : public snort::IpsOption {

  GetterFuncSignature getterFunc;
  bool invert_result;

  IpsOption(Module &module) : snort::IpsOption(s_name),
                              getterFunc(module.get_getter()),
                              invert_result(module.get_invert_result()) {}

  // Hash compare is used as a fast way to compare two instances of IpsOption
  uint32_t hash() const override {
    static_assert(sizeof(getterFunc) <= 8);

    uint64_t p = static_cast<uint64_t>(reinterpret_cast<std::uintptr_t>(getterFunc));

    uint32_t a = static_cast<uint32_t>(p & 0xFFFF'FFFF);
    uint32_t b = static_cast<uint32_t>(p >> 32);
    uint32_t c = invert_result;

    mix(a,b,c);
    finalize(a,b,c);

    return c;
  }

  // If hashes match a real comparison check is made
  bool operator==(const snort::IpsOption &ips) const override {
    const IpsOption &rs = dynamic_cast<const IpsOption &>(ips);
    return getterFunc == rs.getterFunc &&
           invert_result == rs.invert_result;
  }

  EvalStatus eval(Cursor &c, snort::Packet *p) override {
    assert(p);
    PacketFlowData *flow_data = PacketFlowData::get_from_flow(p->flow);
    EvalStatus result = getterFunc(c, flow_data);

    if (invert_result) {
std::cerr << "MKRTEST: Inverting result" << std::endl;
      if (result == snort::IpsOption::MATCH) {
        return snort::IpsOption::NO_MATCH;
      }
      if (result == snort::IpsOption::NO_MATCH) {
        return snort::IpsOption::MATCH;
      }
    }
    return result;
  }

  snort::CursorActionType get_cursor_type() const override {
    return snort::CAT_SET_OTHER;
    //return snort::CAT_ADJUST;
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
