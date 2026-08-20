#ifndef mqtt_protocol_defs_D4A91F6B
#define mqtt_protocol_defs_D4A91F6B

// This file contains helpers and definitions for parsing MQTT messages

// Snort includes

// System includes
#include<cstddef>
#include<optional>
#include<regex>
#include<span>
#include<string_view>
#include<tuple>
#include<vector>

// Global includes

// Local includes
#include"../wrappers/c_string_type.h"
#include"rules.h"

// Debug includes
#include <iostream>


namespace mqtt_plugin {

enum class MsgType {
  Reserved=0,     // Forbidden Reserved
  CONNECT=1,      // Client to Server Connection request
  CONNACK=2,      // Server to Client Connect acknowledgment
  PUBLISH=3,      // Client to Server or Server to Client Publish message
  PUBACK=4,       // Client to Server or Server to Client Publish acknowledgment (QoS 1)
  PUBREC=5,       // Client to Server or Server to Client Publish received (QoS 2 delivery part 1)
  PUBREL=6,       // Client to Server or Server to Client Publish release (QoS 2 delivery part 2)
  PUBCOMP=7,      // Client to Server or Server to Client Publish complete (QoS 2 delivery part 3)
  SUBSCRIBE=8,    // Client to Server Subscribe request
  SUBACK=9,       // Server to Client Subscribe acknowledgment
  UNSUBSCRIBE=10, // Client to Server Unsubscribe request
  UNSUBACK=11,    // Server to Client Unsubscribe acknowledgment
  PINGREQ=12,     // Client to Server PING request
  PINGRESP=13,    // Server to Client PING response
  DISCONNECT=14,  // Client to Server or Server to Client Disconnect notification
  AUTH=15
};

struct ConnectMsg {
  bool user_name_flag = false;
  bool password_flag = false;
  bool will_retain = false;
  uint8_t will_qos = 0;
  bool will_flag = false;
  bool clean_session = false;
  uint16_t keep_alive_timer = 0;
  std::optional<std::span<const uint8_t>> will_topic;
  std::optional<std::span<const uint8_t>> will_message;
  std::optional<std::span<const uint8_t>> user_name;
  std::optional<std::span<const uint8_t>> password;
};

struct ConnAckMsg {
  uint8_t return_code = 0xFF;
};

struct PublishMsg {
  bool dup_flag = false;
  uint8_t qos_level = 0;
  bool retain_flag = false;
  std::span<const uint8_t> topic_name;
  std::optional<uint16_t> message_identifier;  // only for QoS 1 & 2
  std::optional<std::span<const uint8_t>> payload;
};

struct PubAckMsg {
  uint16_t message_identifier;
};

struct PubRecMsg {
  uint16_t message_identifier;
};

struct PubRelMsg {
  bool dup_flag = false;
  uint8_t qos_level = 0;
  uint16_t message_identifier;
};

struct PubCompMsg {
  uint16_t message_identifier;
};

struct SubscribeMsg {
  bool dup_flag = false;
  uint8_t qos_level = 0;
  std::optional<uint16_t> message_identifier = 0;
  uint32_t subscribe_count = 0;   // Number of subscribe entries in payload
  std::optional<std::span<const uint8_t>> payload;
};

struct SubAckMsg {
  uint16_t message_identifier = 0;
  uint32_t granted_count = 0; // Number of granted subscribtions in payload
  std::optional<std::span<const uint8_t>> payload;
};

struct UnsubscribeMsg {
  bool dup_flag = false;
  uint8_t qos_level = 0;
  std::optional<uint16_t> message_identifier = 0;
  uint32_t unsubscribe_count = 0;   // Number of unsubscribe entries in payload
  std::optional<std::span<const uint8_t>> payload;
};

struct UnsubAckMsg {
  uint16_t message_identifier = 0;
};

struct PingReqMsg {

};

struct PingRespMsg {

};

struct DisconnectMsg {

};




#if 0
// TODO: Move stickyBuffer code to wrapper folder when it is ready
using StickyBufferGetter = bool (*)(snort::Packet*, snort::InspectionBuffer&);

template <typename T>
concept StickyBufferEntryConcept =
requires {
  {T::get_cstring() } -> std::same_as<const char *>;
  {T::getter() } -> std::same_as<StickyBufferGetter>;
};

template <trout::templates::FixedString buffer_name, StickyBufferGetter Func>
struct StickyBufferEntry : public trout::templates::CStringType<buffer_name> {
  constexpr static StickyBufferGetter getter() {
    return Func;
  }
};
static_assert(StickyBufferEntryConcept<StickyBufferEntry<"",nullptr>>,
              "StickyBufferEntry is not compliant with StickyBufferEntryConcept");

template <StickyBufferEntryConcept... entry_list>
struct StickyBufferDef {
  constexpr static const char** get_buffers() {
    static const char* buffers[] = {
          entry_list::get_cstring()..., // Expands the list for all buffer names
          nullptr };
    return buffers;
  }
};



//bool getVersion(snort::Packet*, snort::InspectionBuffer&);
//bool getQos(snort::Packet*, snort::InspectionBuffer&);


using StickyBuffers = StickyBufferDef< StickyBufferEntry<"MQTT_PROTOCOL_VERSION", getVersion>,
                                       StickyBufferEntry<"MQTT_QoS", getQos>>;
#endif

inline std::tuple<uint32_t, bool> decode_var_int(const std::span<const uint8_t> &data, std::size_t &read_pos) {
  static constexpr uint8_t MSB = 0b1000'0000;
  static constexpr uint8_t NOT_MSB = 0b0111'1111;

  uint32_t result = 0;

  for(unsigned pos=0;pos<4*7;pos+=7) {
    if (data.size() <= read_pos) {
      break;
    }

    result |= (NOT_MSB & data[read_pos]) << (7*pos);

    if ((MSB & data[read_pos++]) == 0) {
      return {result, true};
    }
  }

  return {0, false};
}


inline std::string to_string(const std::span<const uint8_t> s) {
  return std::string{reinterpret_cast<const char*>(s.data()), s.size()};
}

inline std::string_view to_string_view(const std::span<const uint8_t> s) {
  return std::string_view{reinterpret_cast<const char*>(s.data()), s.size()};
}

inline std::vector<uint8_t> to_vector(const std::span<const uint8_t> s) {
  return {s.begin(), s.end()};
}

inline std::optional<std::span<const uint8_t>> decode_span_16(const std::span<const uint8_t> &data, uint32_t &read_pos) {
  if (read_pos > data.size()) {
    return std::nullopt;
  }

  uint32_t remaining = data.size() - read_pos;
  if (remaining < 2) {
    return std::nullopt;
  }

  uint16_t len = data[read_pos++];
  len <<= 8;
  len |= data[read_pos++];

  remaining += 2;

  if (remaining < len) {
    read_pos+=remaining;
    return std::nullopt;
  }

  if (len == 0) {
    return std::span<const uint8_t>{};
  }

  auto start_of_span = &data[read_pos];

  read_pos += len;

  return std::span<const uint8_t>{start_of_span, len};
}

inline std::optional<uint16_t> decode_uint16(const std::span<const uint8_t> &data, uint32_t &read_pos) {
  if ((read_pos + 2) > data.size()) {
    return std::nullopt;
  }

  uint16_t val = data[read_pos++];
  val <<= 8;
  val |= data[read_pos++];

  return val;
}

inline bool decode_and_check_message_identifier(SID sid, uint16_t &res, const std::span<const uint8_t> &data, uint32_t &read_pos) {
    auto message_identifier = decode_uint16(data, read_pos);

    if (message_identifier) {
      res = *message_identifier;

      if (res != 0) {
        return true;
      }
    }

    queue(sid);

    return !!message_identifier;
}

class FixedHeaderDecode {
  uint8_t byte1;
public:
  FixedHeaderDecode(uint8_t byte1) : byte1(byte1) {};

  uint8_t get_msg_type() {
    return byte1 >> 4;
  }

  bool dup_flag() {
   return byte1 & 0b0000'1000;
  }

  uint8_t qos_level() {
    return (byte1 >> 1) & 0b11;
  }

  bool retain_flag() {
    return byte1 & 0b1;
  }
};

inline bool validate_topic(const std::span<const uint8_t> &span, bool allow_wildcards=true) {
  //const static std::regex wildcard_topic("[^+#]+[+#]?|[+#]", std::regex::optimize);

  // RegEx string that defines legal topics with wildcards in the MQTT3.1 spec Appendix A
  // Note: "(?!$)" is a negative look-ahead stating this can't be the end of the string
  const static std::regex wildcard_topic(R"(/?(?!$)(([^+#/\x00]+|\+)/)*([^+#/\x00]+|[+#]?))", std::regex::optimize);

  // A topic can't have a wildcard or the 0 character in MQTT3.1
  const static std::regex topic(R"(/?(?!$)([^+#/\x00]+/)*[^+#/\x00]?)", std::regex::optimize);

  // std::regex_match works on chars
  auto char_span = std::span<const char>(reinterpret_cast<const char*>(span.data()), span.size());

  if (allow_wildcards) {
    return std::regex_match(char_span.begin(), char_span.end(), wildcard_topic);
  } else {
    return std::regex_match(char_span.begin(), char_span.end(), topic);
  }
}

class SubscribePayloadDecoder {
  std::span<const uint8_t> data;
public:
  struct ValueType {
    std::span<const uint8_t> msg_id;
    uint8_t qos=0;
  };

  SubscribePayloadDecoder(std::span<const uint8_t> data) : data(data) {}

  class Iterator {
    const std::span<const uint8_t> data;
    uint32_t read_pos=0;
  public:
    using value_type = std::optional<ValueType>;
    using difference_type = int32_t;  // We know this is big enough
    using iterator_category = std::forward_iterator_tag;

    Iterator(std::span<const uint8_t> data) : data(data) {}

    value_type operator*() const {
      assert(read_pos >= data.size());

      uint32_t local_read_pos = read_pos;

      auto topic_name = decode_span_16(data, local_read_pos);

      if (!topic_name || local_read_pos >= data.size() ) {
        return std::nullopt;
      }

      uint8_t qos = data[local_read_pos];

      return ValueType{*topic_name, qos};
    }

    Iterator& operator++() {
      assert(read_pos >= data.size());

      auto topic_len = decode_uint16(data, read_pos);

      if (topic_len) {
        read_pos += *topic_len;  // Skip the topic
        read_pos += 1;           // Skip the QoS
      }

      // On any error, become end()
      if (!topic_len || read_pos > data.size()) {
        read_pos = data.size();
      }

      return *this;
    }

    bool operator==(const Iterator& rhs) const {
      assert(data == rhs.data);
      return read_pos == rhs.read_pos;
    }
/*
    bool operator!=(const Iterator& other) const {
      return read_pos != other.read_pos;
    }
*/
    void move_to_end() {
      read_pos = data.size();
    }
  };

  Iterator begin() {
    return Iterator(data);
  }

  Iterator end() {
    Iterator itr(data);
    itr.move_to_end();
    return itr;
  }
};


} // namespace mqtt_plugin

#endif // #ifndef mqtt_protocol_defs_D4A91F6B
