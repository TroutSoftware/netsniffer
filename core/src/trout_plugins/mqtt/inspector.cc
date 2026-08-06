
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes
#include <protocols/packet.h>
#include <stream/stream_splitter.h>

// System includes
#include <algorithm>
#include <array>
#include <span>

// Global includes

// Local includes
#include "flow_data.h"
#include "inspector.h"
#include "module.h"
#include "mqtt_protocol_defs.h"
#include "pegs.h"
#include "stream_splitter.h"

// Debug includes
#include <iostream>

namespace mqtt_plugin {

namespace {



} // namespace


/*
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
*/

void Inspector::decode_connect(snort::Packet *p, PacketFlowData *flow_data) {
    std::span<const uint8_t> data(p->data, p->dsize);
    auto remaining_from_header = flow_data->remaining_from_header;
    auto read_pos = flow_data->variable_header_start;

    // Check the version and markers for that version
    constexpr uint8_t MQTT3_1_ID[]   = {0x00, 0x06, 'M', 'Q', 'I', 's', 'd', 'p', 0x03}; // from 3.1 spec
    constexpr uint8_t MQTT3_1_1_ID[] = {0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04}; // from 3.1.1 spec
    constexpr uint8_t MQTT5_0_ID[]   = {0x00, 0x04, 'M', 'Q', 'T', 'T', 0x05}; // from 5.0 spec

    if (remaining_from_header >= sizeof(MQTT3_1_ID) &&
        (std::ranges::equal(data.subspan(read_pos, sizeof(MQTT3_1_ID)), std::span{MQTT3_1_ID}))) {
      flow_data->protocol_level = 3;
      read_pos += sizeof(MQTT3_1_ID);
    } else if (remaining_from_header >= sizeof(MQTT3_1_1_ID) &&
        (std::ranges::equal(data.subspan(read_pos, sizeof(MQTT3_1_1_ID)), std::span{MQTT3_1_1_ID}))) {
      flow_data->protocol_level = 4;
      read_pos += sizeof(MQTT3_1_1_ID);
    } else if (remaining_from_header >= sizeof(MQTT5_0_ID) &&
        (std::ranges::equal(data.subspan(read_pos, sizeof(MQTT5_0_ID)), std::span{MQTT5_0_ID}))) {
      flow_data->protocol_level = 5;
      read_pos += sizeof(MQTT5_0_ID);
    } else {
      reject(p, "Doesn't contain a valid/known MQTT protocol");
      return;
    }

    const auto protocol_level = flow_data->protocol_level;

    ConnectMsg connect;

    if (protocol_level == 3) {
      if (remaining_from_header < 1 + read_pos) {
        queue(SID::connect_message_malformed);
        return;
      }
      connect.user_name_flag = data[read_pos] & (1<<7);
      connect.password_flag = data[read_pos] & (1<<6);
      connect.will_retain = data[read_pos] & (1<<5);
      connect.will_qos = (data[read_pos] >> 3) & 0b11;
      connect.will_flag = data[read_pos] & (1<<2);
      connect.clean_session = data[read_pos] & (1<<1);
      read_pos++;

      // QoS is only allowed to be 0,1,2
      if (connect.will_qos >= 3) {
        queue(SID::connect_message_malformed);
      }

      if (remaining_from_header < 2 + read_pos) {
        queue(SID::connect_message_malformed);
        return;
      }

      connect.keep_alive_timer = data[read_pos++];
      connect.keep_alive_timer <<= 8;
      connect.keep_alive_timer |= data[read_pos++];

      auto client_id = decode_span_16(data, read_pos);

      if (!client_id || client_id->size() < 1) {
        queue(SID::connect_message_malformed);
        return;
      }

      flow_data->client_id = to_vector(*client_id);

      if (connect.will_flag) {
        auto will_topic = decode_span_16(data, read_pos);
        auto will_message = decode_span_16(data, read_pos);  // legal to have zero length

        if (!will_topic || !will_message || will_topic->size() < 1) {
          queue(SID::connect_message_malformed);
          return;
        }

        // 3.1 standard states all bytes in the Will Message must be 7-bit
        if (std::ranges::any_of(*will_message, [](uint8_t c) { return c > 0x7F; })) {
          queue(SID::connect_message_malformed);
          return;
        }

        connect.will_topic = *will_topic;
        connect.will_message = *will_message;
      }

      if (connect.user_name_flag) {
        // It is not illegal in 3.1 to have a missing user_name, even the flag was set
        connect.user_name = decode_span_16(data, read_pos);
      }

      if (connect.password_flag) {
        // It is not illegal in 3.1 to have a missing password, even the flag was set
        connect.password = decode_span_16(data, read_pos);
      }

      // If at this point the read_pos is not equal to the total length
      // something is spooky
      if(read_pos <= remaining_from_header) {
std::cerr << "MKRTEST: Got extra data in connect msg" << std::endl;
        connect.extra = data.subspan(read_pos, remaining_from_header - read_pos);
        queue(SID::message_has_extra_data);
      } else {
std::cerr << "MKRTEST: Connect fully parsed" << std::endl;
      }

      flow_data->cur_msg = connect;
    }

}

void Inspector::reject(snort::Packet *p, std::string reason) {
  // TODO: Add logging
  snort::WarningMessage("MQTT inspector received an invalid packet (%s)\n", reason.c_str());

  if (p->flow) {
    p->flow->set_service(p, 0);
  }
}

void Inspector::eval(snort::Packet *p) {
  assert(p);
  assert(p->data);

  // Wrap the incomming data in a safe container
  std::span<const uint8_t> data(p->data, p->dsize);

  std::cerr << "MKRTEST: eval called with pkt len " << p->pktlen
            << " datalen " << p->dsize << std::endl;


  std::size_t read_pos = 1;
  uint32_t remaining;
  bool success;
  std::tie(remaining, success) = decode_var_int(data, read_pos);

  if (!success) {
    reject(p, "MQTT packages doesn't have valid fixed header");
    return;
  }


  std::cerr << "MKRTEST: Remaning length is " << remaining << std::endl;

  PacketFlowData *flow_data = PacketFlowData::get_from_flow(p->flow);
  assert(flow_data);

  // Check if stream is considered in sync
  if (!flow_data->in_sync) {
    // TODO: Flag out of sync event
std::cerr << "MKRTEST: Flow out of sync" << std::endl;
    return;
  }

  if (remaining != p->dsize - read_pos) {
    // TODO: Flag as truncated
    flow_data->in_sync = false;
std::cerr << "MKRTEST: Package is missing data, going out of sync" << std::endl;
    return;
  }

  MsgType msg_type = static_cast<MsgType>(data[0] >> 4);
  flow_data->msg_type = msg_type;

  flow_data->remaining_from_header = remaining;
  flow_data->variable_header_start = read_pos;


//std::cerr << "MKRTEST: Flow no " << flow_data->flow_no << std::endl;
std::cerr << "MKRTEST: got msg_type " << (data[0] >> 4) << std::endl;

  if (flow_data->protocol_level == 0) {
    // Our first packet must be a connect, otherwise we reject it from being MQTT
    if (msg_type != MsgType::CONNECT) {
      reject(p, "MQTT communication must start with a CONNECT message");
      return;
    }
    return decode_connect(p, flow_data);
  }

  switch(msg_type) {
    case MsgType::Reserved:
    case MsgType::CONNECT:
    case MsgType::CONNACK:
    case MsgType::PUBLISH:
    case MsgType::PUBACK:
    case MsgType::PUBREC:
    case MsgType::PUBREL:
    case MsgType::PUBCOMP:
    case MsgType::SUBSCRIBE:
    case MsgType::SUBACK:
    case MsgType::UNSUBSCRIBE:
    case MsgType::UNSUBACK:
    case MsgType::PINGREQ:
    case MsgType::PINGRESP:
    case MsgType::DISCONNECT:
    case MsgType::AUTH:
std::cerr << "MKRTEST: Don't know how to handle msg type: " << (int)msg_type << std::endl;
      return;
  }


}

void Inspector::clear(snort::Packet*p) {
  assert(p);
  PacketFlowData *flow_data = PacketFlowData::get_from_flow(p->flow);

  // Some cur_msg's refer to the packet data, so we should cleanup
  // when the packet is being destructed
  flow_data->cur_msg = std::monostate{};
}


snort::StreamSplitter* Inspector::get_splitter(bool to_server) {
  return new StreamSplitter(to_server);
}

Inspector::Inspector(Module *module) : settings(module->get_settings()) {
std::cerr << "MKRTEST MQTT Inspector created" << std::endl;
}

Inspector::~Inspector() {}

snort::Inspector *Inspector::ctor(snort::Module *module) {
  return new Inspector(dynamic_cast<Module *>(module));
}

void Inspector::dtor(snort::Inspector *p) { delete p; }

} // namespace mqtt_plugin
