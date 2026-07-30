
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes
#include <protocols/packet.h>
#include <stream/stream_splitter.h>

// System includes
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

  MsgType msg_type = static_cast<MsgType>(data[0] >> 4);

//std::cerr << "MKRTEST: Flow no " << flow_data->flow_no << std::endl;
std::cerr << "MKRTEST: got msg_type " << (data[0] >> 4) << std::endl;

  if (flow_data->protocol_level == 0) {
    // Our first packet must be a connect, otherwise we reject it from being MQTT
    if (msg_type != MsgType::CONNECT) {
      reject(p, "MQTT communication must start with a CONNECT message");
      return;
    }

    // Check the version and markers for that version
    constexpr uint8_t MQTT3_1_ID[]   = {0x00, 0x06, 'M', 'Q', 'I', 's', 'd', 'p', 0x03}; // from 3.1 spec
    constexpr uint8_t MQTT3_1_1_ID[] = {0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04}; // from 3.1.1 spec
    constexpr uint8_t MQTT5_0_ID[]   = {0x00, 0x04, 'M', 'Q', 'T', 'T', 0x06}; // from 5.0 spec

    if (remaining >= sizeof(MQTT3_1_ID) &&
        (std::ranges::equal(data.subspan(read_pos, sizeof(MQTT3_1_ID)), std::span{MQTT3_1_ID}))) {
      flow_data->protocol_level = 3;
    } else if (remaining >= sizeof(MQTT3_1_1_ID) &&
        (std::ranges::equal(data.subspan(read_pos, sizeof(MQTT3_1_1_ID)), std::span{MQTT3_1_1_ID}))) {
      flow_data->protocol_level = 4;
    } else if (remaining >= sizeof(MQTT5_0_ID) &&
        (std::ranges::equal(data.subspan(read_pos, sizeof(MQTT5_0_ID)), std::span{MQTT5_0_ID}))) {
      flow_data->protocol_level = 5;
    } else {
      reject(p, "Doesn't contain a valid/known MQTT protocol");
      return;
    }

  }



}


snort::StreamSplitter* Inspector::get_splitter(bool to_server) {
  return new StreamSplitter(to_server);
}

Inspector::Inspector(Module *module) : settings(module->get_settings()) {}

Inspector::~Inspector() {}

snort::Inspector *Inspector::ctor(snort::Module *module) {
  return new Inspector(dynamic_cast<Module *>(module));
}

void Inspector::dtor(snort::Inspector *p) { delete p; }

} // namespace mqtt_plugin
