#ifndef mqtt_protocol_defs_D4A91F6B
#define mqtt_protocol_defs_D4A91F6B

// This file contains helpers and definitions for parsing MQTT messages

// Snort includes

// System includes
#include<cstddef>
#include<optional>
#include<span>
#include<string_view>
#include<tuple>
#include<vector>

// Global includes

// Local includes
#include"../wrappers/c_string_type.h"

// Debug includes

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



bool getVersion(snort::Packet*, snort::InspectionBuffer&);
bool getQos(snort::Packet*, snort::InspectionBuffer&);


using StickyBuffers = StickyBufferDef< StickyBufferEntry<"MQTT_PROTOCOL_VERSION", getVersion>,
                                       StickyBufferEntry<"MQTT_QoS", getQos>>;



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

} // namespace mqtt_plugin

#endif // #ifndef mqtt_protocol_defs_D4A91F6B
