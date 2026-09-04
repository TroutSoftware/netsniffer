#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes
#include <framework/module.h>
#include <framework/range.h>
#include <hash/hash_key_operations.h>
#include <log/messages.h>
#include <protocols/packet.h>

// System includes
#include <concepts>
#include <functional>
#include <map>
#include <regex>
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
     "Field requested (E.g. \"mqtt_field: Flow.ClientID;\")"},
    {"match", snort::Parameter::PT_STRING, nullptr, nullptr,
    "Will be a rule match if match string is in the MQTT topic list (Matches are done with # and + wildcards, following the MQTT rules)" },
    {"!match", snort::Parameter::PT_STRING, nullptr, nullptr,
    "Will be a rule match if match string is NOT in the MQTT topic list (Matches are done with # and + wildcards, following the MQTT rules)" },
    {"range_match", snort::Parameter::PT_STRING, nullptr, nullptr,
    "For numeric fields, will be a rule match if value matches match string (Matches are done with eg \">3\", \"=1\", \"<=100\", \"10<>20\" (beween 10 and 20), \"10<=>20\" (between/eqaul to 10 and/or 20) )" },
    {"!range_match", snort::Parameter::PT_STRING, nullptr, nullptr,
    "For numeric fields, will be a rule match if value DOESN'T matches match string (Matches are done with eg \">3\", \"=1\", \"<=100\", \"10<>20\" (beween 10 and 20), \"10<=>20\" (between/eqaul to 10 and/or 20) )" },
    {"regex", snort::Parameter::PT_STRING, nullptr, nullptr,
    "Will be a rule match if match string is in the field or topic list (Matches are done as complete string matches with modified ECMAScript regex)" },
    {"!regex", snort::Parameter::PT_STRING, nullptr, nullptr,
    "Will be a rule match if match string is NOT in the field or topic list (Matches are done as complete string matches with modified ECMAScript regex)" },
    

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

snort::IpsOption::EvalStatus evaluate(Cursor &c, bool &val) {
  c.set("MQTT.bool", reinterpret_cast<const uint8_t*>(&val), sizeof(bool));
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
  virtual bool match(const Cursor&, const PacketFlowData&) = 0;
  virtual ~Match(){};

  template <std::derived_from<Match> T> static std::shared_ptr<Match> factory(std::string &match_string) {
    auto obj = std::make_shared<T>();
    obj->match_string = match_string;
    if (!obj->validate_match_string()) {
      return nullptr;
    }
    return obj;
  }

  static std::string get_name() {
    return "match";
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


template <typename T>
requires (
  // These types found in MQTT can safely be assigned to an int64_t
  std::same_as<T, uint8_t> ||
  std::same_as<T, uint16_t> ||
  std::same_as<T, uint32_t>
)
std::optional<int64_t> get_val(const T &val){
  return val;
}

template<typename T>
std::optional<int64_t> get_val(const std::optional<T> &val) {
  if (val) {
    return get_val(*val);
  }
  return std::nullopt;
}


template<auto member>
// TODO: Make the requires work
//requires IsMsgType<member>
class RangeMatch : public Match {
  snort::RangeCheck rc;
  bool valid = false;
public:
  static std::string get_name() {
    return "range_match";
  }
  
  RangeMatch() {
    rc.init();
  }

  virtual bool validate_match_string() override {
    valid = rc.parse(get_match_string().c_str());
    return valid;
  }

  bool match(const Cursor&, const PacketFlowData& flow_data) override {

    std::optional<int64_t> val;

    if constexpr (IsFlowDataMember<member>) {
      val = get_val(&flow_data->*member);
    } else {
      using ClassType = ClassTypeFinder<decltype(member)>::ClassType;

      if (auto p = std::get_if<ClassType>(&(flow_data.cur_msg))) {
        val = get_val(p->*member);
      }
    }
    return val && rc.eval(*val);
  }

  Hash hash() const override {
    return rc.hash();
  }

};

class TopicMatch : public Match {
public:
  virtual bool validate_match_string() override {
    auto& s = get_match_string();
    std::span<const uint8_t> match_string(reinterpret_cast<const uint8_t *>(s.data()), s.size());

    return validate_topic(match_string, true);
  }

  bool match(const Cursor &c, const PacketFlowData&) override {
    auto& s = get_match_string();
    std::span<const uint8_t> match_string(reinterpret_cast<const uint8_t *>(s.data()), s.size());

    // Add the cursor buffer to a container that can split it into individual parts
    std::span<const uint8_t> cursor_string(c.start(), c.length());

    return topic_match<true, false>(match_string, cursor_string);
  }

};

class RegExMatch : public Match {
  std::optional<std::regex> regex;
public:
  static std::string get_name() {
    return "regex";
  }

  virtual bool validate_match_string() override {
    auto& s = get_match_string();

    try {
      regex = std::regex(s.begin(), s.end());
    } catch (...) {
      return false;
    }

    return true;
  }


  bool run_regex(const char *p, size_t size) {
    if (!regex && !validate_match_string()) {
      return false;
    }

    assert(regex);
    
    std::span<const char> match_string(p, size);

    return std::regex_match(match_string.begin(), match_string.end(), *regex);        
  }

  bool run_regex(const uint8_t *p, size_t size) {
    return run_regex(reinterpret_cast<const char *>(p), size);
  }

  bool run_regex(std::span<const uint8_t> data) {
    return run_regex(data.data(), data.size());
  }

  bool match(const Cursor &c, const PacketFlowData&) override {

    assert(regex);
        
    return run_regex(c.start(), c.length());        
  }

};

class SubscribeRegExMatch : public RegExMatch {
public:
  bool match(const Cursor& c, const PacketFlowData& ) override {

    std::span<const uint8_t> span(c.start(), c.length());
    SubscribePayloadDecoder data(span);

    for( auto ele: data) {
      // if ele is not set, we have an incomming packet that was invalid
      // this is not the place to capture that, the inspector would
      // already have flagged it
      if (ele && run_regex(ele->topic_id)) {
        return true;
      }
    }

    return false;
  }
};


class SubscribeMatch : public Match {

public:
  bool validate_match_string() override {
    auto& s = get_match_string();
    std::span<const uint8_t> match_string(reinterpret_cast<const uint8_t *>(s.data()), s.size());

    return validate_topic(match_string, true);
  }

  bool match(const Cursor& c, const PacketFlowData& ) override {
    auto& s = get_match_string();
    std::span<const uint8_t> match_string(reinterpret_cast<const uint8_t *>(s.data()), s.size());

    // Add the cursor buffer to a container that can split it into individual parts
    std::span<const uint8_t> span(c.start(), c.length());
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

class UnsubscribeRegExMatch : public RegExMatch {
public:  
  bool match(const Cursor& c, const PacketFlowData& ) override {

    std::span<const uint8_t> span(c.start(), c.length());
    UnsubscribePayloadDecoder data(span);

    for( auto ele: data) {
      // if ele is not set, we have an incomming packet that was invalid
      // this is not the place to capture that, the inspector would
      // already have flagged it
      if (ele && run_regex(*ele)) {
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

  bool match(const Cursor &c, const PacketFlowData&) override {
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
  struct Element {
    MatchFactory mf;
    std::string name;
  };
  std::vector<Element> match_factory_list;  

  template <typename T>
    requires std::derived_from<T, Match>
  static Element m() {  // Using a short func name as it is used frequently below
    return {Match::factory<T>, T::get_name()};
  }

  FieldDef(GetterFuncSignature getter) : getter(getter) {}
  FieldDef(GetterFuncSignature getter, Element match_factory) : getter(getter), match_factory_list{match_factory} {}
  FieldDef(GetterFuncSignature getter, std::vector<Element> match_factory_list) : getter(getter), match_factory_list(std::move(match_factory_list)) {}
};



static const std::map<const std::string, const FieldDef> mqtt_field_map  {
// clang-format off
  {"Flow.ClientID",                 {uni_getter<&FlowData::client_id>,                FieldDef::m<RegExMatch>()}},   // Valid for all messages
  {"Flow.ProtocolLevel",            {uni_getter<&FlowData::protocol_level>,           FieldDef::m<RangeMatch<&FlowData::protocol_level>>()}},

  // Checks message
  {"Msg.Connect",                    uni_msg<MsgType::CONNECT>},
  {"Msg.ConnAck",                    uni_msg<MsgType::CONNACK>},
  {"Msg.Publish",                    uni_msg<MsgType::PUBLISH>},
  {"Msg.PubAck",                     uni_msg<MsgType::PUBACK>},
  {"Msg.PubRec",                     uni_msg<MsgType::PUBREC>},
  {"Msg.PubRel",                     uni_msg<MsgType::PUBREL>},
  {"Msg.PubComp",                    uni_msg<MsgType::PUBCOMP>},
  {"Msg.Subscribe",                  uni_msg<MsgType::SUBSCRIBE>},
  {"Msg.SubAck",                     uni_msg<MsgType::SUBACK>},
  {"Msg.Unsubscribe",                uni_msg<MsgType::UNSUBSCRIBE>},
  {"Msg.UnsubAck",                   uni_msg<MsgType::UNSUBACK>},
  {"Msg.PingReq",                    uni_msg<MsgType::PINGREQ>},
  {"Msg.PingResp",                   uni_msg<MsgType::PINGRESP>},
  {"Msg.Disconnect",                 uni_msg<MsgType::DISCONNECT>},
  {"Msg.Auth",                       uni_msg<MsgType::AUTH, 5>},     // Only for 5.0

  // Common message data
  {"Msg.Extra",                      uni_getter<&FlowData::extra>},

  // Valid for Connect message, fields will return NO_MATCH if not found in message
  // NOTE: messages can be present but empty and will return MATCH in that case
  {"Connect.WillTopic",             {uni_getter<&ConnectMsg::will_topic>,            {FieldDef::m<TopicMatch>(), FieldDef::m<RegExMatch>()}}},
  {"Connect.WillMessage",           {uni_getter<&ConnectMsg::will_message>,           FieldDef::m<RegExMatch>()}},
  {"Connect.WillQoS",               {uni_getter<&ConnectMsg::will_qos>,               FieldDef::m<RangeMatch<&ConnectMsg::will_qos>>()}},
  {"Connect.UserName",              {uni_getter<&ConnectMsg::user_name>,              FieldDef::m<RegExMatch>()}},
  {"Connect.Password",              {uni_getter<&ConnectMsg::password>,               FieldDef::m<RegExMatch>()}},
  // Connect flags will return MATCH if found, NO_MATCH if not found, flags will not move cursor
  {"Connect.Flag.WillRetain",        uni_getter<&ConnectMsg::will_retain>},
  {"Connect.Flag.CleanSession",      uni_getter<&ConnectMsg::clean_session>},

  {"ConnAck.ReturnCode",            {uni_getter<&ConnAckMsg::return_code>,            FieldDef::m<RangeMatch<&ConnAckMsg::return_code>>()}},

  {"Publish.Flag.Retain",            uni_getter<&PublishMsg::retain_flag>},
  {"Publish.Flag.Dup",               uni_getter<&PublishMsg::dup_flag>},
  {"Publish.Topic",                 {uni_getter<&PublishMsg::topic_name>,            {FieldDef::m<TopicMatch>(), FieldDef::m<RegExMatch>()}}},
  {"Publish.MessageIdentifier",      uni_getter<&PublishMsg::message_identifier>},
  {"Publish.Payload" ,              {uni_getter<&PublishMsg::payload>,                FieldDef::m<RegExMatch>()}},
  {"Publish.QoS",                   {uni_getter<&PublishMsg::qos_level>,              FieldDef::m<RangeMatch<&PublishMsg::qos_level>>()}},

  {"PubAck.MessageIdentifier",       uni_getter<&PubAckMsg::message_identifier>},

  {"PubRec.MessageIdentifier",       uni_getter<&PubRecMsg::message_identifier>},

  {"PubRel.Flag.Dup",                uni_getter<&PubRelMsg::dup_flag>},
  {"PubRel.QoS",                    {uni_getter<&PubRelMsg::qos_level>,               FieldDef::m<RangeMatch<&PubRelMsg::qos_level>>()}},
  {"PubRel.MessageIdentifier",       uni_getter<&PubRelMsg::message_identifier>},

  {"PubComp.MessageIdentifier",      uni_getter<&PubCompMsg::message_identifier>},

  {"Subscribe.Flag.Dup",             uni_getter<&SubscribeMsg::dup_flag>},
  {"Subscribe.QoS",                 {uni_getter<&SubscribeMsg::qos_level>,            FieldDef::m<RangeMatch<&SubscribeMsg::qos_level>>()}},
  {"Subscribe.MessageIdentifier",    uni_getter<&SubscribeMsg::message_identifier>},
  {"Subscribe.SubscribeCount",      {uni_getter<&SubscribeMsg::subscribe_count>,      FieldDef::m<RangeMatch<&SubscribeMsg::subscribe_count>>()}},
  {"Subscribe.Payload",             {uni_getter<&SubscribeMsg::payload>,             {FieldDef::m<SubscribeMatch>(), FieldDef::m<SubscribeRegExMatch>()}}},
  {"Subscribe.Topic",               {uni_getter<&SubscribeMsg::payload>,             {FieldDef::m<SubscribeMatch>(), FieldDef::m<SubscribeRegExMatch>()}}},

  {"SubAck.MessageIdentifier",       uni_getter<&SubAckMsg::message_identifier>},
  {"SubAck.GrantedCount",           {uni_getter<&SubAckMsg::granted_count>,           FieldDef::m<RangeMatch<&SubAckMsg::granted_count>>()}},
  {"SubAck.Payload",                 uni_getter<&SubAckMsg::payload>},

  {"Unsubscribe.Flag.Dup",           uni_getter<&UnsubscribeMsg::dup_flag>},
  {"Unsubscribe.QoS",               {uni_getter<&UnsubscribeMsg::qos_level>,          FieldDef::m<RangeMatch<&UnsubscribeMsg::qos_level>>()}},
  {"Unsubscribe.MessageIdentifier",  uni_getter<&UnsubscribeMsg::message_identifier>},
  {"Unsubscribe.UnsubscribeCount",  {uni_getter<&UnsubscribeMsg::unsubscribe_count>,  FieldDef::m<RangeMatch<&UnsubscribeMsg::unsubscribe_count>>()}},
  {"Unsubscribe.Payload",           {uni_getter<&UnsubscribeMsg::payload>,           {FieldDef::m<UnsubscribeMatch>(), FieldDef::m<UnsubscribeRegExMatch>()}}},
  {"Unsubscribe.Topic",             {uni_getter<&UnsubscribeMsg::payload>,           {FieldDef::m<UnsubscribeMatch>(), FieldDef::m<UnsubscribeRegExMatch>()}}},

  {"UnsubAck.MessageIdentifier",     uni_getter<&UnsubAckMsg::message_identifier>},
// clang-format on
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
    } else {
      if (!field) {
        snort::ErrorMessage("matching keywords need to be preceded by a valid field name\n");
        return false;
      }

      if (field->match_factory_list.empty()) {
        snort::ErrorMessage("match keyword is not supported by %s fields\n", settings->field_name.c_str());
        return false;
      }
  
      std::string s = val.get_name();
      if (s.size() == 0) {
        snort::ErrorMessage("keyword can't be empty\n");
        return false;
      }
      bool negate = s[0] == '!';
      if (negate) {
        s.erase(0, 1);  // Remove the '!'
        if (s.size() == 0) {
          snort::ErrorMessage("keyword can't be empty, ! means negate\n");
          return false;
        }
      }
        
      for (auto& ele : field->match_factory_list) {

        if (s == ele.name) {

          std::string match_string = val.get_unquoted_string();
          std::shared_ptr<Match> matchObj = ele.mf(match_string);
          
          if (!matchObj) {
            snort::ErrorMessage("match string '%s' is invalid\n", match_string.c_str());
            return false;
          }

          settings->match_list.emplace_back(matchObj, negate);
          return true;
        }
      }

      snort::ErrorMessage("ERROR: The mqtt_field %s supports: ", settings->field_name.c_str());
      for (auto& ele : field->match_factory_list) {
        snort::ErrorMessage("%s ", ele.name.c_str());
      }
      snort::ErrorMessage("\n");
      
      return false;
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
