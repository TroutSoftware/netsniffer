#ifndef mqtt_protocol_defs_D4A91F6B
#define mqtt_protocol_defs_D4A91F6B

// Snort includes

// System includes
#include<cstddef>
#include<span>
#include<tuple>

// Global includes

// Local includes

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

inline std::tuple<uint32_t, bool> decode_var_int(std::span<const uint8_t> &data, std::size_t &read_pos) {
  static const uint8_t MSB = 0b1000'0000;
  static const uint8_t NOT_MSB = 0b0111'1111;

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

} // namespace mqtt_plugin

#endif // #ifndef mqtt_protocol_defs_D4A91F6B
