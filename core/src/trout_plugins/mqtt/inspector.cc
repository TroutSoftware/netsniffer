
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
#include "rules.h"
#include "stream_splitter.h"

// Debug includes
#include <iostream>

namespace mqtt_plugin {

namespace {



} // namespace

void Inspector::decode_connect(snort::Packet *p, PacketFlowData &flow_data) {
  const std::span<const uint8_t> data(p->data, p->dsize);
  auto read_pos = flow_data.variable_header_start;

  // Check the version and markers for that version
  constexpr uint8_t MQTT3_1_ID[]   = {0x00, 0x06, 'M', 'Q', 'I', 's', 'd', 'p', 0x03}; // from 3.1 spec
  constexpr uint8_t MQTT3_1_1_ID[] = {0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04}; // from 3.1.1 spec
  constexpr uint8_t MQTT5_0_ID[]   = {0x00, 0x04, 'M', 'Q', 'T', 'T', 0x05}; // from 5.0 spec

  if (data.size() >= read_pos + sizeof(MQTT3_1_ID) &&
      (std::ranges::equal(data.subspan(read_pos, sizeof(MQTT3_1_ID)), std::span{MQTT3_1_ID}))) {
    flow_data.protocol_level = 3;
    read_pos += sizeof(MQTT3_1_ID);
  } else if (data.size() >= read_pos + sizeof(MQTT3_1_1_ID) &&
      (std::ranges::equal(data.subspan(read_pos, sizeof(MQTT3_1_1_ID)), std::span{MQTT3_1_1_ID}))) {
    flow_data.protocol_level = 4;
    read_pos += sizeof(MQTT3_1_1_ID);
  } else if (data.size() >= read_pos + sizeof(MQTT5_0_ID) &&
      (std::ranges::equal(data.subspan(read_pos, sizeof(MQTT5_0_ID)), std::span{MQTT5_0_ID}))) {
    flow_data.protocol_level = 5;
    read_pos += sizeof(MQTT5_0_ID);
  } else {
    reject(p, "Doesn't contain a valid/known MQTT protocol");
    return;
  }

  const auto protocol_level = flow_data.protocol_level;

  ConnectMsg connect;

  if (protocol_level == 3) {
    if (data.size() <= read_pos) {
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

    if (data.size() < 2 + read_pos) {
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

    flow_data.client_id = to_vector(*client_id);

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
    assert(read_pos <= data.size());
    if(read_pos < data.size()) {
      flow_data.extra = data.subspan(read_pos);
      queue(SID::message_has_extra_data);
    }

    flow_data.cur_msg = connect;
  } else {
    snort::WarningMessage("MQTT inspector received a connect message but doesn't support protocol level %i\n", protocol_level);
  }

}

void Inspector::decode_connack(snort::Packet *p, PacketFlowData &flow_data) {
  const std::span<const uint8_t> data(p->data, p->dsize);
  auto read_pos = flow_data.variable_header_start;
  const auto protocol_level = flow_data.protocol_level;

  if (protocol_level == 3) {
    ConnAckMsg connack;
    if (data.size() >= read_pos + 2) {
      read_pos++;  // Byte 0 is reserved
      uint8_t return_code = data[read_pos++];

      if (return_code > 5) {
        queue(SID::connack_message_malformed);
      }

      if (return_code != 0) {
        flow_data.connection_refused = true;
      }
    }

    // If at this point the read_pos is not equal to the total length
    // something is spooky
    assert(read_pos <= data.size());
    if(read_pos < data.size()) {
      flow_data.extra = data.subspan(read_pos);
      queue(SID::message_has_extra_data);
    }

    flow_data.cur_msg = connack;
  } else {
    snort::WarningMessage("MQTT inspector received a connack message but doesn't support protocol level %i\n", protocol_level);
  }
}

void Inspector::decode_publish(snort::Packet *p, PacketFlowData &flow_data) {
  std::span<const uint8_t> data(p->data, p->dsize);
  auto read_pos = flow_data.variable_header_start;
  const auto protocol_level = flow_data.protocol_level;

  if (protocol_level == 3) {
    PublishMsg publish;

    FixedHeaderDecode fh(data[0]);

    publish.dup_flag = fh.dup_flag();
    publish.qos_level = fh.qos_level();
    publish.retain_flag = fh.retain_flag();

    if (publish.qos_level >= 3) {
      queue(SID::publish_message_malformed);
      // We won't know if there should be a Message ID or not later...
      return;
    }

    auto topic_name = decode_span_16(data, read_pos);

    if (!topic_name) {
      queue(SID::publish_message_malformed);
      return;
    }

    if (topic_name->size() == 0 || topic_name->size() > 0x7FFFF ) {
      queue(SID::topic_name_invalid);
    }

    publish.topic_name = *topic_name;

    if (publish.qos_level != 0) {
      uint16_t message_identifier = 0;
      if(!decode_and_check_message_identifier(SID::publish_message_malformed,
                                          message_identifier,
                                          data, read_pos)) {
        return;
      }
      publish.message_identifier = message_identifier;
    }

    // A payload isn't mandatory, but if it is there it will take the
    // rest of the message
    assert(read_pos <= data.size());
    if (read_pos < data.size()) {
      publish.payload = data.subspan(read_pos);
    }

    flow_data.cur_msg = publish;
  } else {
    snort::WarningMessage("MQTT inspector received a publish message but doesn't support protocol level %i\n", protocol_level);
  }

}

void Inspector::decode_puback(snort::Packet *p, PacketFlowData &flow_data) {
  std::span<const uint8_t> data(p->data, p->dsize);
  auto read_pos = flow_data.variable_header_start;
  const auto protocol_level = flow_data.protocol_level;

  if (protocol_level == 3) {
    PubAckMsg puback;

    if(!decode_and_check_message_identifier(SID::puback_message_malformed,
                                        puback.message_identifier,
                                        data, read_pos)) {
      return;
    }

    // If at this point the read_pos is not equal to the total length
    // something is spooky
    assert(read_pos <= data.size());
    if(read_pos < data.size()) {
      flow_data.extra = data.subspan(read_pos);
      queue(SID::message_has_extra_data);
    }

    flow_data.cur_msg = puback;
  } else {
    snort::WarningMessage("MQTT inspector received a puback message but doesn't support protocol level %i\n", protocol_level);
  }
}

void Inspector::decode_pubrec(snort::Packet *p, PacketFlowData &flow_data) {
  std::span<const uint8_t> data(p->data, p->dsize);
  auto read_pos = flow_data.variable_header_start;
  const auto protocol_level = flow_data.protocol_level;

  if (protocol_level == 3) {
    PubRecMsg pubrec;

    if(!decode_and_check_message_identifier(SID::pubrec_message_malformed,
                                        pubrec.message_identifier,
                                        data, read_pos)) {
      return;
    }

    // If at this point the read_pos is not equal to the total length
    // something is spooky
    assert(read_pos <= data.size());
    if(read_pos < data.size()) {
      flow_data.extra = data.subspan(read_pos);
      queue(SID::message_has_extra_data);
    }

    flow_data.cur_msg = pubrec;
  } else {
    snort::WarningMessage("MQTT inspector received a pubrec message but doesn't support protocol level %i\n", protocol_level);
  }
}

void Inspector::decode_pubrel(snort::Packet *p, PacketFlowData &flow_data) {
  std::span<const uint8_t> data(p->data, p->dsize);
  auto read_pos = flow_data.variable_header_start;
  const auto protocol_level = flow_data.protocol_level;

  if (protocol_level == 3) {
    PubRelMsg pubrel;

    FixedHeaderDecode fh(data[0]);

    pubrel.dup_flag = fh.dup_flag();
    pubrel.qos_level = fh.qos_level();

    if(!decode_and_check_message_identifier(SID::pubrel_message_malformed,
                                        pubrel.message_identifier,
                                        data, read_pos)) {
      return;
    }

    // If at this point the read_pos is not equal to the total length
    // something is spooky
    assert(read_pos <= data.size());
    if(read_pos < data.size()) {
      flow_data.extra = data.subspan(read_pos);
      queue(SID::message_has_extra_data);
    }

    flow_data.cur_msg = pubrel;
  } else {
    snort::WarningMessage("MQTT inspector received a pubrel message but doesn't support protocol level %i\n", protocol_level);
  }
}

void Inspector::decode_pubcomp(snort::Packet *p, PacketFlowData &flow_data) {
  std::span<const uint8_t> data(p->data, p->dsize);
  auto read_pos = flow_data.variable_header_start;
  const auto protocol_level = flow_data.protocol_level;

  if (protocol_level == 3) {
    PubCompMsg pubcomp;

    if(!decode_and_check_message_identifier(SID::pubcomp_message_malformed,
                                        pubcomp.message_identifier,
                                        data, read_pos)) {
      return;
    }

    // If at this point the read_pos is not equal to the total length
    // something is spooky
    assert(read_pos <= data.size());
    if(read_pos < data.size()) {
      flow_data.extra = data.subspan(read_pos);
      queue(SID::message_has_extra_data);
    }

    flow_data.cur_msg = pubcomp;
  } else {
    snort::WarningMessage("MQTT inspector received a pubcomp message but doesn't support protocol level %i\n", protocol_level);
  }
}

void Inspector::decode_subscribe(snort::Packet *p, PacketFlowData &flow_data) {
  std::span<const uint8_t> data(p->data, p->dsize);
  auto read_pos = flow_data.variable_header_start;
  const auto protocol_level = flow_data.protocol_level;

  if (protocol_level == 3) {
    SubscribeMsg subscribe;

    FixedHeaderDecode fh(data[0]);

    subscribe.dup_flag = fh.dup_flag();
    subscribe.qos_level = fh.qos_level();

    if (subscribe.qos_level >= 3) {
      queue(SID::subscribe_message_malformed);
      // We won't know if there should be a Message ID or not later...
      return;
    }

    if (subscribe.qos_level != 0) {
      uint16_t message_identifier;

      if(!decode_and_check_message_identifier(SID::subscribe_message_malformed,
                                          message_identifier,
                                          data, read_pos)) {
        return;
      }

      subscribe.message_identifier = message_identifier;
    }

    if (read_pos < data.size()) {
      subscribe.payload = data.subspan(read_pos);
    }

    // Validate the payload
    while (read_pos < data.size()) {
      auto topic_name_len = decode_uint16(data, read_pos);
      if (!topic_name_len) {
        // No topic name
        queue(SID::subscribe_message_malformed);
        break;
      }

      read_pos += *topic_name_len;

      if (read_pos+1 <= data.size()) {
        // No Qos
        queue(SID::subscribe_message_malformed);
        break;
      }

      uint8_t topic_qos = data[read_pos++] & 0b0000'0011;

      if (topic_qos > 2) {
        queue(SID::subscribe_message_malformed);
        flow_data.connection_refused = true;      // Spec says connection should be closed
        break;
      }

      subscribe.subscribe_count++;
    }

    flow_data.cur_msg = subscribe;
  } else {
    snort::WarningMessage("MQTT inspector received a subscribe message but doesn't support protocol level %i\n", protocol_level);
  }
}

void Inspector::decode_suback(snort::Packet *p, PacketFlowData &flow_data) {
  std::span<const uint8_t> data(p->data, p->dsize);
  auto read_pos = flow_data.variable_header_start;
  const auto protocol_level = flow_data.protocol_level;

  if (protocol_level == 3) {
    SubAckMsg suback;

    if(!decode_and_check_message_identifier(SID::suback_message_malformed,
                                        suback.message_identifier,
                                        data, read_pos)) {
      return;
    }

    if (read_pos < data.size()) {
      suback.payload = data.subspan(read_pos);
    }

    // We know that read_pos can't be bigger than data.size bc it is checked
    suback.granted_count = data.size() - read_pos;

    while (read_pos < data.size()) {
      uint8_t granted_qos = data[read_pos++] & 0b0000'0011;

      if (granted_qos > 2) {
        queue(SID::suback_message_malformed);
        break;
      }
    }

    flow_data.cur_msg = suback;
  } else {
    snort::WarningMessage("MQTT inspector received a suback message but doesn't support protocol level %i\n", protocol_level);
  }
}

void Inspector::decode_unsubscribe(snort::Packet *p, PacketFlowData &flow_data) {
  std::span<const uint8_t> data(p->data, p->dsize);
  auto read_pos = flow_data.variable_header_start;
  const auto protocol_level = flow_data.protocol_level;

  if (protocol_level == 3) {
    UnsubscribeMsg unsubscribe;

    FixedHeaderDecode fh(data[0]);

    unsubscribe.dup_flag = fh.dup_flag();
    unsubscribe.qos_level = fh.qos_level();

    if (unsubscribe.qos_level >= 3) {
      queue(SID::unsubscribe_message_malformed);
      // We won't know if there should be a Message ID or not later...
      return;
    }

    if (unsubscribe.qos_level != 0) {
      uint16_t message_identifier;

      if(!decode_and_check_message_identifier(SID::unsubscribe_message_malformed,
                                          message_identifier,
                                          data, read_pos)) {
        return;
      }

      unsubscribe.message_identifier = message_identifier;
    }

    if (read_pos < data.size()) {
      unsubscribe.payload = data.subspan(read_pos);
    }

    // Validate the payload
    while (read_pos < data.size()) {
      auto topic_name_len = decode_uint16(data, read_pos);
      if (!topic_name_len) {
        // No topic name
        queue(SID::unsubscribe_message_malformed);
        break;
      }

      read_pos += *topic_name_len;

      if (read_pos > data.size()) {
        queue(SID::unsubscribe_message_malformed);
        break;
      }

      unsubscribe.unsubscribe_count++;
    }

    flow_data.cur_msg = unsubscribe;
  } else {
    snort::WarningMessage("MQTT inspector received an unsubscribe message but doesn't support protocol level %i\n", protocol_level);
  }
}

void Inspector::decode_unsuback(snort::Packet *p, PacketFlowData &flow_data) {
  std::span<const uint8_t> data(p->data, p->dsize);
  auto read_pos = flow_data.variable_header_start;
  const auto protocol_level = flow_data.protocol_level;

  if (protocol_level == 3) {
    UnsubAckMsg unsuback;

    if(!decode_and_check_message_identifier(SID::unsuback_message_malformed,
                                        unsuback.message_identifier,
                                        data, read_pos)) {
      return;
    }

    // If at this point the read_pos is not equal to the total length
    // something is spooky
    assert(read_pos <= data.size());
    if(read_pos < data.size()) {
      flow_data.extra = data.subspan(read_pos);
      queue(SID::message_has_extra_data);
    }

    flow_data.cur_msg = unsuback;
  } else {
    snort::WarningMessage("MQTT inspector received a suback message but doesn't support protocol level %i\n", protocol_level);
  }
}

void Inspector::decode_pingreq(snort::Packet *p, PacketFlowData &flow_data) {
  std::span<const uint8_t> data(p->data, p->dsize);
  auto read_pos = flow_data.variable_header_start;
  const auto protocol_level = flow_data.protocol_level;

  if (protocol_level == 3) {
    PingReqMsg pingreq;

    // If at this point the read_pos is not equal to the total length
    // something is spooky
    assert(read_pos <= data.size());
    if(read_pos < data.size()) {
      flow_data.extra = data.subspan(read_pos);
      queue(SID::message_has_extra_data);
    }

    flow_data.cur_msg = pingreq;
  } else {
    snort::WarningMessage("MQTT inspector received a pingreq message but doesn't support protocol level %i\n", protocol_level);
  }
}

void Inspector::decode_pingresp(snort::Packet *p, PacketFlowData &flow_data) {
  std::span<const uint8_t> data(p->data, p->dsize);
  auto read_pos = flow_data.variable_header_start;
  const auto protocol_level = flow_data.protocol_level;

  if (protocol_level == 3) {
    PingRespMsg pingresp;

    // If at this point the read_pos is not equal to the total length
    // something is spooky
    assert(read_pos <= data.size());
    if(read_pos < data.size()) {
      flow_data.extra = data.subspan(read_pos);
      queue(SID::message_has_extra_data);
    }

    flow_data.cur_msg = pingresp;
  } else {
    snort::WarningMessage("MQTT inspector received a pingresp message but doesn't support protocol level %i\n", protocol_level);
  }
}


void Inspector::decode_disconnect(snort::Packet *p, PacketFlowData &flow_data) {
  std::span<const uint8_t> data(p->data, p->dsize);
  auto read_pos = flow_data.variable_header_start;
  const auto protocol_level = flow_data.protocol_level;

  if (protocol_level == 3) {
    DisconnectMsg disconnect;

    // If at this point the read_pos is not equal to the total length
    // something is spooky
    assert(read_pos <= data.size());
    if(read_pos < data.size()) {
      flow_data.extra = data.subspan(read_pos);
      queue(SID::message_has_extra_data);
    }

    flow_data.cur_msg = disconnect;
  } else {
    snort::WarningMessage("MQTT inspector received a disconnect message but doesn't support protocol level %i\n", protocol_level);
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

  if (remaining != p->dsize - read_pos) {
    if (p->is_from_client()) {
      flow_data->client_in_sync = false;
    } else {
      flow_data->server_in_sync = false;
    }
  }

  if (p->is_from_client() && !flow_data->client_in_sync) {
    queue(SID::client_out_of_sync);
    return;
  }

  if (p->is_from_server() && !flow_data->server_in_sync) {
    queue(SID::server_out_of_sync);
    return;
  }

  if (flow_data->connection_refused) {
    queue(SID::com_on_refused_connection);
    // No return, as we can still decode messages
  }

  MsgType msg_type = static_cast<MsgType>(data[0] >> 4);
  flow_data->msg_type = msg_type;

  //flow_data->remaining_from_header = remaining;
  flow_data->variable_header_start = read_pos;

std::cerr << "MKRTEST: Flow id " << flow_data->flow_id << std::endl;
std::cerr << "MKRTEST: got msg_type " << (data[0] >> 4) << std::endl;

  if (flow_data->protocol_level == 0) {
    // Our first packet must be a connect, otherwise we reject it from being MQTT
    if (msg_type != MsgType::CONNECT) {
      reject(p, "MQTT communication must start with a CONNECT message");
      return;
    }
    return decode_connect(p, *flow_data);
  }

  switch(msg_type) {
    case MsgType::CONNACK:
      return decode_connack(p, *flow_data);

    case MsgType::PUBLISH:
      return decode_publish(p, *flow_data);

    case MsgType::PUBACK:
      return decode_puback(p, *flow_data);

    case MsgType::PUBREC:
      return decode_pubrec(p, *flow_data);

    case MsgType::PUBREL:
      return decode_pubrel(p, *flow_data);

    case MsgType::PUBCOMP:
      return decode_pubcomp(p, *flow_data);

    case MsgType::SUBSCRIBE:
      return decode_subscribe(p, *flow_data);

    case MsgType::SUBACK:
      return decode_suback(p, *flow_data);

    case MsgType::UNSUBSCRIBE:
      return decode_unsubscribe(p, *flow_data);

    case MsgType::UNSUBACK:
      return decode_unsuback(p, *flow_data);

    case MsgType::PINGREQ:
      return decode_pingreq(p, *flow_data);

    case MsgType::PINGRESP:
      return decode_pingresp(p, *flow_data);

    case MsgType::DISCONNECT:
      return decode_disconnect(p, *flow_data);

    case MsgType::Reserved:
    case MsgType::CONNECT:
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

  // Msg type is no longer relevant
  flow_data->msg_type = MsgType::Reserved;

  flow_data->extra.reset();
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
