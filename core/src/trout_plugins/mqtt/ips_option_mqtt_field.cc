#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes
#include <framework/module.h>
#include <hash/hash_key_operations.h>
#include <log/messages.h>
#include <protocols/packet.h>

// System includes
#include <concepts>
#include <functional>
#include <map>
#include <string>
#include <typeinfo>

// Global includes

// Local includes
#include "flow_data.h"
#include "ips_option_mqtt_field.h"
#include "mqtt_protocol_defs.h"

// Debug includes
#include <iostream>

namespace mqtt_plugin {
namespace {

using Hash = uint32_t;

template <typename T>
Hash to_hash(T v) {
  uint64_t hash = std::hash<T>{}(v);
  uint32_t a = static_cast<uint32_t>(hash & 0xFFFF'FFFF);
  uint32_t b = static_cast<uint32_t>(hash >> 32);
  uint32_t c = 0;
  mix(a, b, c);
  finalize(a, b, c);
  return c;
}


static const char *s_name = "mqtt_field";

static const char *s_help = "moves cursor to given field";

static const snort::Parameter module_params[] = {
    {"~", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Field requested"},
    {"match", snort::Parameter::PT_STRING, nullptr, nullptr,
    "Will be a rule match if match string is in the MQTT topic list (Matches are done with # and + wildcards, following the MQTT rules)" },
    {"!match", snort::Parameter::PT_STRING, nullptr, nullptr,
    "Will be a rule match if match string is NOT in the MQTT topic list (Matches are done with # and + wildcards, following the MQTT rules)" },

    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

const PegInfo s_pegs[] = {
    {CountType::SUM, "invocations", "Number of times a packet was searced"},
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

template<MsgType t, uint8_t from_version = 0>
snort::IpsOption::EvalStatus uni_msg(Cursor &, PacketFlowData &flow_data) {
  if constexpr (from_version != 0) {
    if (from_version > flow_data.protocol_level ) {
      return snort::IpsOption::NO_MATCH;
    }
  }

  return (flow_data.msg_type == t)?snort::IpsOption::MATCH:snort::IpsOption::NO_MATCH;
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

class Match {
  std::string match_string;
public:
  const std::string &get_match_string() const {
    return match_string;
  }

  virtual bool validate_match_string() = 0;   // Returns false on invalid string format
  virtual bool match(const Cursor &) = 0;
  virtual ~Match(){};

  template <std::derived_from<Match> T> static std::shared_ptr<Match> factory(std::string &match_string) {
    auto obj = std::make_shared<T>();
    obj->match_string = match_string;
    if (!obj->validate_match_string()) {
      return nullptr;
    }
    return obj;
  }

  // Should only be overridden if the derived class has data/state
  // members that will impact matching
  virtual bool operator==(const Match &rhs) const {
    return typeid(*this) == typeid(rhs) &&
           match_string == rhs.match_string;
  }

  virtual Hash hash() const {
    Hash a = to_hash(typeid(*this).hash_code());
    Hash b = to_hash(match_string);
    Hash c = 0;

    mix(a, b, c);
    finalize(a, b, c);

    return c;
  }
};

using MatchFactory = std::shared_ptr<Match> (*)(std::string &);

class TopicMatch : public Match {
public:
  virtual bool validate_match_string() override {
    auto& s = get_match_string();
    std::span<const uint8_t> match_string(reinterpret_cast<const uint8_t *>(s.data()), s.size());

    return validate_topic(match_string, true);
  }

  bool match(const Cursor &c) override {
    auto& s = get_match_string();
    std::span<const uint8_t> match_string(reinterpret_cast<const uint8_t *>(s.data()), s.size());

    // Add the cursor buffer to a container that can split it into individual parts
    std::span<const uint8_t> cursor_string(c.buffer(), c.size());

    return topic_match<true, false>(match_string, cursor_string);
  }

};


class SubscribeMatch : public Match {

public:
  bool validate_match_string() override {
    auto& s = get_match_string();
    std::span<const uint8_t> match_string(reinterpret_cast<const uint8_t *>(s.data()), s.size());

    return validate_topic(match_string, true);
  }

  bool match(const Cursor &c) override {
    auto& s = get_match_string();
    std::span<const uint8_t> match_string(reinterpret_cast<const uint8_t *>(s.data()), s.size());

    // Add the cursor buffer to a container that can split it into individual parts
    std::span<const uint8_t> span(c.buffer(), c.size());
    SubscribePayloadDecoder data(span);

    for( auto ele: data) {
      // if ele is not set, we have an incomming packet that was invalid
      // this is not the place to capture that, the inspector would
      // already have flagged it
      if (ele && topic_match<true, true>(match_string, ele->topic_id)) {
        return true;
      }
    }

    return false;
  }
};

class UnsubscribeMatch : public Match {

public:
  bool validate_match_string() override {
    auto& s = get_match_string();
    std::span<const uint8_t> match_string(reinterpret_cast<const uint8_t *>(s.data()), s.size());

    return validate_topic(match_string, true);
  }

  bool match(const Cursor &c) override {
    auto& s = get_match_string();
    std::span<const uint8_t> match_string(reinterpret_cast<const uint8_t *>(s.data()), s.size());

    // Add the cursor buffer to a container that can split it into individual parts
    std::span<const uint8_t> span(c.buffer(), c.size());
    UnsubscribePayloadDecoder data(span);

    for( auto ele: data) {
      // if ele is not set, we have an incomming packet that was invalid
      // this is not the place to capture that, the inspector would
      // already have flagged it
      if (ele && topic_match<true, true>(match_string, *ele)) {
        return true;
      }
    }

    return false;
  }
};


struct FieldDef {
  GetterFuncSignature getter;
  MatchFactory match_factory;

  FieldDef(GetterFuncSignature getter, MatchFactory match_factory = nullptr) : getter(getter), match_factory(match_factory) {}
};

static const std::map<const std::string, const FieldDef> mqtt_field_map  {

  {"Flow.ClientID", uni_getter<&FlowData::client_id>},   // Valid for all messages
  {"Flow.ProtocolLevel", uni_getter<&FlowData::protocol_level>},

  // Checks message
  {"Msg.Connect", uni_msg<MsgType::CONNECT>},
  {"Msg.ConnAck", uni_msg<MsgType::CONNACK>},
  {"Msg.Publish", uni_msg<MsgType::PUBLISH>},
  {"Msg.PubAck", uni_msg<MsgType::PUBACK>},
  {"Msg.PubRec", uni_msg<MsgType::PUBREC>},
  {"Msg.PubRel", uni_msg<MsgType::PUBREL>},
  {"Msg.PubComp", uni_msg<MsgType::PUBCOMP>},
  {"Msg.Subscribe", uni_msg<MsgType::SUBSCRIBE>},
  {"Msg.SubAck", uni_msg<MsgType::SUBACK>},
  {"Msg.Unsubscribe", uni_msg<MsgType::UNSUBSCRIBE>},
  {"Msg.UnsubAck", uni_msg<MsgType::UNSUBACK>},
  {"Msg.PingReq", uni_msg<MsgType::PINGREQ>},
  {"Msg.PingResp", uni_msg<MsgType::PINGRESP>},
  {"Msg.Disconnect", uni_msg<MsgType::DISCONNECT>},
  {"Msg.Auth", uni_msg<MsgType::AUTH, 5>},     // Only for 5.0

  // Common message data
  {"Msg.Extra", uni_getter<&FlowData::extra>},

  // Valid for Connect message, fields will return NO_MATCH if not found in message
  // NOTE: messages can be present but empty and will return MATCH in that case
  {"Connect.WillTopic", {uni_getter<&ConnectMsg::will_topic>, Match::factory<TopicMatch>}},
  {"Connect.WillMessage", uni_getter<&ConnectMsg::will_message>},
  {"Connect.UserName", uni_getter<&ConnectMsg::user_name>},
  {"Connect.Password", uni_getter<&ConnectMsg::password>},
  // Connect flags will return MATCH if found, NO_MATCH if not found, flags will not move cursor
  {"Connect.Flag.WillRetain", uni_getter<&ConnectMsg::will_retain>},
  {"Connect.Flag.CleanSession", uni_getter<&ConnectMsg::clean_session>},

  // TODO: Add: Connect.will_qos uint8_t will_qos = 0;
  {"ConnAck.ReturnCode", uni_getter<&ConnAckMsg::return_code>},

  {"Publish.Flag.Retain", uni_getter<&PublishMsg::retain_flag>},
  {"Publish.Flag.Dup", uni_getter<&PublishMsg::dup_flag>},
  {"Publish.Topic", {uni_getter<&PublishMsg::topic_name>, Match::factory<TopicMatch>}},
  {"Publish.MessageIdentifier", uni_getter<&PublishMsg::message_identifier>},
  {"Publish.Payload" , uni_getter<&PublishMsg::payload>},
  // TODO: Add: Publish qos compare func

  {"PubAck.MessageIdentifier", uni_getter<&PubAckMsg::message_identifier>},

  {"PubRec.MessageIdentifier", uni_getter<&PubRecMsg::message_identifier>},

  {"PubRel.Flag.Dup", uni_getter<&PubRelMsg::dup_flag>},
  // TODO: Add: PubRelMsg qos compare func
  {"PubRel.MessageIdentifier", uni_getter<&PubRelMsg::message_identifier>},

  {"PubComp.MessageIdentifier", uni_getter<&PubCompMsg::message_identifier>},

  {"Subscribe.Flag.Dup", uni_getter<&SubscribeMsg::dup_flag>},
  // TODO: Add: Subscribe qos comparer func
  {"Subscribe.MessageIdentifier", uni_getter<&SubscribeMsg::message_identifier>},
  {"Subscribe.SubscribeCount", uni_getter<&SubscribeMsg::subscribe_count>},
  {"Subscribe.Payload", {uni_getter<&SubscribeMsg::payload>, Match::factory<SubscribeMatch>}},
  {"Subscribe.Topic", {uni_getter<&SubscribeMsg::payload>, Match::factory<SubscribeMatch>}},

  {"SubAck.MessageIdentifier", uni_getter<&SubAckMsg::message_identifier>},
  {"SubAck.GrantedCount", uni_getter<&SubAckMsg::granted_count>},
  {"SubAck.Payload", uni_getter<&SubAckMsg::payload>},

  {"Unsubscribe.Flag.Dup", uni_getter<&UnsubscribeMsg::dup_flag>},
  // TODO: Add: Unsubscribe qos comparer func
  {"Unsubscribe.MessageIdentifier", uni_getter<&UnsubscribeMsg::message_identifier>},
  {"Unsubscribe.UnsubscribeCount", uni_getter<&UnsubscribeMsg::unsubscribe_count>},
  {"Unsubscribe.Payload", {uni_getter<&UnsubscribeMsg::payload>, Match::factory<UnsubscribeMatch>}},
  {"Unsubscribe.Topic", {uni_getter<&UnsubscribeMsg::payload>, Match::factory<UnsubscribeMatch>}},

  {"UnsubAck.MessageIdentifier", uni_getter<&UnsubAckMsg::message_identifier>},
};

struct MatchRule {
  std::shared_ptr<Match>  matcher;
  bool                    invert_result;
  bool operator==(const MatchRule &rhs) const {
    return invert_result == rhs.invert_result &&
           ((!matcher && !rhs.matcher) || (
           matcher && rhs.matcher &&
           *matcher == *rhs.matcher));
  }

  Hash hash() const {
    Hash a = (matcher)?matcher->hash():0;
    Hash b = invert_result;
    Hash c = 0;

    mix(a, b, c);
    finalize(a, b, c);

    return c;
  }

};

struct Settings {
  GetterFuncSignature getter_func = dummy_getter;
  bool invert_result = false;
  std::vector<MatchRule> match_list;

  // field_name is only added to make snort errors/warnings more
  // specific / context aware
  //
  // The field name isn't part of the hash, or compare evaluation, the
  // other members capture the state of this settings object
  std::string field_name;


  bool operator==(const Settings &rhs) const {
    return invert_result == rhs.invert_result &&
           getter_func == rhs.getter_func &&
           match_list == rhs.match_list;
  }

  Hash hash() const {
    Hash a = to_hash(getter_func);
    Hash b = invert_result;
    Hash c = match_list.size();

    mix(a, b, c);

    size_t i = 0;

    while (i + 2 < match_list.size()) {
      a += match_list[i++].hash();
      b += match_list[i++].hash();
      c += match_list[i++].hash();

      mix(a, b, c);
    }

    if (i != match_list.size()) {
      a += match_list[i++].hash();

      if (i != match_list.size()) {
        b += match_list[i++].hash();
      }

      mix(a, b, c);
    }

    finalize(a, b, c);

    return c;
  }
};

class Module : public snort::Module {
  std::shared_ptr<Settings> settings = std::make_shared<Settings>();
  std::optional<FieldDef> field;

  Module() : snort::Module(s_name, s_help, module_params) {}

  bool begin(const char *, int, snort::SnortConfig *) override {
    settings = std::make_shared<Settings>();
    field.reset();
    return true;
  }

  bool end(const char *, int, snort::SnortConfig *) override {
    field.reset();
    return settings->getter_func != dummy_getter;
  }

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("~")) {
      std::string s = val.get_as_string();

      // Check if results should be negated
      if (s.size()>=1 && s[0] == '!') {
        settings->invert_result = true;
        s.erase(0, 1);
      }

      auto field_itr = mqtt_field_map.find(s);

      if (field_itr == mqtt_field_map.end()) {
        return false;
      }

      field = field_itr->second;

      settings->getter_func = field->getter;
      settings->field_name = val.get_as_string();
      return true;
    } else if (val.is("match") || val.is("!match")) {
      if (!field) {
        snort::ErrorMessage("match keyword need to be preceded by a valid field name\n");
        return false;
      }

      if (!field->match_factory) {
        snort::ErrorMessage("match keyword is not supported by %s fields\n", settings->field_name.c_str());
        return false;
      }

      // Create a match object
      std::string match_string = val.get_unquoted_string();
      std::shared_ptr<Match> matchObj = field->match_factory(match_string);

      if (!matchObj) {
        snort::ErrorMessage("match string '%s' is invalid\n", match_string.c_str());
        return false;
      }

      std::string s = val.get_name();
      settings->match_list.emplace_back(matchObj, s[0] == '!');

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

  std::shared_ptr<Settings> get_settings() { return settings; }
};

class IpsOption : public snort::IpsOption {
  std::shared_ptr<Settings> settings;

  IpsOption(Module &module) : snort::IpsOption(s_name),
                              settings(module.get_settings()) {}

  // Hash compare is used as a fast way to compare two instances of IpsOption
  uint32_t hash() const override {
    return settings->hash();
  }

  // If hashes match a real comparison check is made
  bool operator==(const snort::IpsOption &ips) const override {
    const IpsOption &rs = dynamic_cast<const IpsOption &>(ips);
    return *settings == *rs.settings;
  }

  EvalStatus eval(Cursor &c, snort::Packet *p) override {
    assert(p);
    PacketFlowData *flow_data = PacketFlowData::get_from_flow(p->flow);
    EvalStatus result = settings->getter_func(c, *flow_data);

    // Check if a filter should be applied
    if (result == snort::IpsOption::MATCH && settings->match_list.size() != 0) {
      // We assume no match, until proven otherwise
      result = snort::IpsOption::NO_MATCH;
      for (auto &ele : settings->match_list) {
        assert( ele.matcher );
        bool matches = ele.matcher->match(c);

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
