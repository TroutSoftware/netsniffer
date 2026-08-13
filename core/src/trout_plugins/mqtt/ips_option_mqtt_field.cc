#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes
#include <framework/module.h>
#include <hash/hash_key_operations.h>
#include <protocols/packet.h>

// System includes
#include <concepts>
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

using GetterFuncSignature = snort::IpsOption::EvalStatus(*)(Cursor &, PacketFlowData &);

snort::IpsOption::EvalStatus dummy_getter(Cursor &, PacketFlowData&) {
  return snort::IpsOption::NO_MATCH;
}


template<typename T>
// TODO: Add concept to check if T is valid type to check with std::get_if
snort::IpsOption::EvalStatus uni_msg(Cursor &, PacketFlowData &flow_data) {
  if (std::get_if<T>(&(flow_data.cur_msg))) {
    return snort::IpsOption::MATCH;
  }

  return snort::IpsOption::NO_MATCH;
}


template<typename T> struct optional_traits;
template<typename T> struct optional_traits<std::optional<T>>{
  using ContainedType = T;
};

snort::IpsOption::EvalStatus evaluate(Cursor &/*c*/, bool val) {
  return val?snort::IpsOption::MATCH:snort::IpsOption::NO_MATCH;
}

snort::IpsOption::EvalStatus evaluate(Cursor &c, std::span<const uint8_t> &val) {
  c.set("MQTT.span", val.data(), val.size());
  return snort::IpsOption::MATCH;
}

snort::IpsOption::EvalStatus evaluate(Cursor &c, std::vector<uint8_t> &val) {
  c.set("MQTT.vector", val.data(), val.size());
  return snort::IpsOption::MATCH;
}

template<std::integral T>
snort::IpsOption::EvalStatus evaluate(Cursor &c, T &val) {
  c.set("MQTT.integral", reinterpret_cast<const uint8_t*>(&val), sizeof(T));
  return snort::IpsOption::MATCH;
}


template<typename T>
snort::IpsOption::EvalStatus evaluate(Cursor &c, std::optional<T> &val) {
  if (val) {
    return evaluate(c, *val);
  }
  return snort::IpsOption::NO_MATCH;
}


template<typename> struct ClassTypeFinder;

template<typename M, typename C> struct ClassTypeFinder<M C::*> {
  using ClassType = C;
  using MemberType = M;
};

template<auto member>
concept IsFlowDataMember =
  std::same_as<FlowData, typename ClassTypeFinder<decltype(member)>::ClassType>;

template<auto member>
requires IsFlowDataMember<member>
snort::IpsOption::EvalStatus uni_getter(Cursor &c, PacketFlowData &flow_data)
{
  return evaluate(c, &flow_data->*member);
}

template<typename T, typename V, size_t... I>
constexpr size_t count_t_in_v_helper(std::index_sequence<I...>) {
  return (size_t{std::same_as<T, std::variant_alternative_t<I, V>>} + ...);
}

template<typename T, typename V>
constexpr size_t count_t_in_v() {
  return count_t_in_v_helper<T, V> (
    std::make_index_sequence<std::variant_size_v<V>>{} );
};

template<auto T>
concept IsMsgType =
requires (PacketFlowData &flow_data) {
  (count_t_in_v_helper<T, decltype(flow_data.cur_msg)>() == 1);
};

template<auto member>
// TODO: Make the requires work
//requires IsMsgType<member>
snort::IpsOption::EvalStatus uni_getter(Cursor &c, PacketFlowData &flow_data)
{
  //using MemberType = ClassTypeFinder<decltype(member)>::MemberType;
  using ClassType = ClassTypeFinder<decltype(member)>::ClassType;

  if (auto p = std::get_if<ClassType>(&(flow_data.cur_msg))) {
    return evaluate(c, p->*member);
  }

  return snort::IpsOption::NO_MATCH;
}

static const std::map<std::string, GetterFuncSignature> mqtt_field_map  {

  {"Flow.ClientID", uni_getter<&FlowData::client_id>},   // Valid for all messages
  {"Flow.ProtocolLevel", uni_getter<&FlowData::protocol_level>},

  // Checks message
  {"Msg.Connect", uni_msg<ConnectMsg>},
  {"Msg.ConnAck", uni_msg<ConnAckMsg>},
  {"Msg.Publish", uni_msg<PublishMsg>},
  {"Msg.PubAck", uni_msg<PubAckMsg>},
  {"Msg.PubRec", uni_msg<PubRecMsg>},

  // Common message data
  {"Msg.Extra", uni_getter<&FlowData::extra>},

  // Valid for Connect message, fields will return NO_MATCH if not found in message
  // NOTE: messages can be present but empty and will return MATCH in that case
  {"Connect.WillTopic", uni_getter<&ConnectMsg::will_topic>},
  {"Connect.WillMessage", uni_getter<&ConnectMsg::will_message>},
  {"Connect.UserName", uni_getter<&ConnectMsg::user_name>},
  {"Connect.Password", uni_getter<&ConnectMsg::password>},
  // Connect flags will return MATCH if found, NO_MATCH if not found, flags will not move cursor
  {"Connect.Flag.WillRetain", uni_getter<&ConnectMsg::will_retain>},
  {"Connect.Flag.CleanSession", uni_getter<&ConnectMsg::clean_session>},

  // TODO: Add: Connect.will_qos uint8_t will_qos = 0;
  {"ConnAck.ReturnCode", uni_getter<&ConnAckMsg::return_code>},

  {"Publish.Flag.Retain", &uni_getter<&PublishMsg::retain_flag>},
  {"Publish.Flag.Dup", &uni_getter<&PublishMsg::dup_flag>},
  {"Publish.TopicName", &uni_getter<&PublishMsg::topic_name>},
  {"Publish.MessageIdentifier", uni_getter<&PublishMsg::message_identifier>},
  {"Publish.Payload" , uni_getter<&PublishMsg::payload>},
  // TODO: Add: Publish qos compare func

  {"PubAck.MessageIdentifier", uni_getter<&PubAckMsg::message_identifier>},

  {"PubRec.MessageIdentifier", uni_getter<&PubRecMsg::message_identifier>},

};


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
        invert_result = true;
        s.erase(0, 1);
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
    EvalStatus result = getterFunc(c, *flow_data);

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
