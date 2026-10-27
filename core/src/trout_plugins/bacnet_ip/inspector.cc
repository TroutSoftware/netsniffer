
// this file is WIP

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes
#include <protocols/packet.h>

// System includes
#include <cstddef>
#include <span>

// Global includes

// Local includes
#include "bacnet_ip_defs.h"
#include "inspector.h"
#include "module.h"
#include "pegs.h"

// Debug includes
#include <iostream>

namespace bacnet_ip {

void Inspector::eval(snort::Packet *p) {
  assert(p);
  assert(p->data);

  Pegs::get<"packages_received">().inc();

  if (!p->is_udp()) {
    return;
  }

  Pegs::get<"udp_packages_received">().inc();

  // Wrap the incoming data in a container,
  // Ideally we would be using at() instead of [] to access the data, but
  // that is a C++26 feature and we are currently on C++23
  std::span<const uint8_t> data(p->data, p->dsize);
  std::size_t read_pos = 0;
  
  // Decode bvlc
  if (data.size() < read_pos + BVLC_SIZE) {
    // Not enough data for a complete bvlc
    Pegs::get<"packet_underflow">().inc();
    return;
  }

  if (data[read_pos++] != BVLS_BACNET_IP_TYPE) {
    return;
  }

  uint8_t msg_function = data[read_pos++];
  
  uint16_t msg_len = data[read_pos++];
  msg_len <<= 8;
  msg_len |= data[read_pos++];
  
  assert(read_pos <= data.size());

  if (msg_len > data.size()) {
    // Not enough data for the rest of the message
std::cerr << "MKRTEST - length is " << msg_len << " but package only has " << data.size() << " bytes of data" << std::endl;
    Pegs::get<"packet_underflow">().inc();
    return;
  }

  if (msg_len < data.size()) {
    // udp packet contains data that isn't part of the message
    Pegs::get<"packet_extra_data">().inc();
    Pegs::get<"packet_extra_data_sum">().add(data.size() - msg_len);
  }

  // Decode NPDU
  if (data.size() < read_pos + NPDU_MIN_SIZE) {
    // Not enough data for a minimum NDPU
    Pegs::get<"packet_underflow">().inc();
    return;
  }

  //uint8_t version = data[read_pos++];

  //uint8_t control_byte = data[read_pos++];

  //bool is_network_layer = control_byte & NPDU_IS_NETWORK_LAYER_MASK;
  //bool has_dest_mask = control_byte & NPDU_HAS_DEST_MASK;
  //bool has_src_mask = control_byte & NPDU_HAS_SRC_MASK;
  //bool reply_expected = control_byte & NPDU_REPLY_EXPECT_MASK;
  //uint8_t priority = control_byte & NPDU_PRIORITY_MASK;

  // TODO: Decode the NPDU

  Pegs::get<"bacnet_ip_packets_received">().inc();

  std::cerr << "MKRTEST - got msg_function: " << msg_function << " msg length: " << msg_len << std::endl;
}

Inspector::Inspector(Module *module) : settings(module->get_settings()) {}

Inspector::~Inspector() {}

snort::Inspector *Inspector::ctor(snort::Module *module) {
  return new Inspector(dynamic_cast<Module *>(module));
}

void Inspector::dtor(snort::Inspector *p) { delete p; }

} // namespace bacnet_ip
