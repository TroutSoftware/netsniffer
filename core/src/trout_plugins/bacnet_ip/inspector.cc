
// this file is WIP

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes
#include <protocols/packet.h>

// System includes
#include <cstddef>
#include <optional>
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


namespace {

class NPDUReader {
  const std::span<const uint8_t> &data;
  std::size_t &read_pos;
  bool underflow = false;
  
  bool has_data(size_t length) {
    if (underflow) {
      return false;
    }
    if (data.size() < read_pos + length && length > 0) {
      Pegs::get<"packet_underflow">().inc();
      
      underflow = true;
      return false;
    }
    
    return true;
  }

  std::optional<uint8_t> read_uint8_t() {
    if (has_data(sizeof(uint8_t))) {
      return data[read_pos++];
    }
    
    return std::nullopt;    
  }

  std::optional<uint16_t> read_uint16_t() {
    if (has_data(sizeof(uint16_t))) {
      uint16_t val = data[read_pos++];
      val <<= 8;
      val |= data[read_pos++];
      return val;
    }
    return std::nullopt;
  }

  std::optional<std::span<const uint8_t>> read_span(size_t length) {
    if (has_data(length)) {
      std::span<const uint8_t> val(&data[read_pos], length);
      read_pos += length;

      return val;
    }

    return std::nullopt;
  }

  std::optional<uint8_t> version;
  std::optional<uint8_t> control_byte;

  std::optional<uint16_t> dest_network;
  std::optional<bool> is_broadcast;
  std::optional<std::span<const uint8_t>> dest_addr;

  std::optional<uint16_t> src_network;
  std::optional<std::span<const uint8_t>> src_addr;
  std::optional<uint8_t> hop_count;

  std::optional<uint8_t> msg_type;
  std::optional<uint16_t> vendor_id;

  std::optional<std::span<const uint8_t>> apdu;
  std::optional<std::span<const uint8_t>> network_msg;
  
public:
  NPDUReader(const std::span<const uint8_t> &data, std::size_t &read_pos, bool ignore_version) : data(data), read_pos(read_pos) {
    version = read_uint8_t();

    if (version != 1) {
      Pegs::get<"unsupported_protocol_version">().inc();
      if (!ignore_version) {
        return;
      }
    }
    
    control_byte = read_uint8_t();

    // Bail if we didn't get a control_byte
    if(!control_byte.has_value()) {
      return;
    }
    // Decode control byte
    bool is_network_layer = *control_byte & NPDU_IS_NETWORK_LAYER_MASK;
    bool has_dest_mask = *control_byte & NPDU_HAS_DEST_MASK;
    bool has_src_mask = *control_byte & NPDU_HAS_SRC_MASK;
    [[maybe_unused]]bool reply_expected = *control_byte & NPDU_REPLY_EXPECT_MASK;
    uint8_t priority = *control_byte & NPDU_PRIORITY_MASK;

    if (has_dest_mask) {
      dest_network = read_uint16_t();
      std::optional<uint16_t> len = read_uint8_t();
      
      if (len.has_value()) {
        // A len of 0 means the msg is a broadcast
        is_broadcast = (*len == 0);

        if (*len > NPDU_MAX_ADDRESS_LENGTH) {
          Pegs::get<"spec_violations">().inc();
        }
        
        if (*len) {         
          dest_addr = read_span(*len);          
        }
      }
    }

    if (has_src_mask) {
      src_network = read_uint16_t();
      std::optional<uint16_t> len = read_uint8_t();
      
      if (len.has_value()) {
        if (*len > NPDU_MAX_ADDRESS_LENGTH || len == 0) {
          Pegs::get<"spec_violations">().inc();
        }
        
        if (*len) {         
          src_addr = read_span(*len);          
        }
      }
      
    }

    if (has_dest_mask) {
      hop_count = read_uint8_t();
    }

    if (is_network_layer) {
      msg_type = read_uint8_t();

      if (msg_type && *msg_type == BACNET_MSG_TYPE_FIRST_VENDOR_RANGE) {
        vendor_id = read_uint16_t();
      }

      if (data.size() >= read_pos) {
        auto rest = data.size() - read_pos;
        network_msg = read_span(rest);
      }
    } else {
      if (data.size() >= read_pos) {
        auto rest = data.size() - read_pos;
        apdu = read_span(rest);
      }
    }



if(underflow) {
std::cerr << "MKRTEST msg had data underflow" << std::endl;
}

std::cerr << "MKRTEST version: " << (int)*version << std::endl;
std::cerr << "MKRTEST priority: " << (int)priority << std::endl;;
if (has_dest_mask) {
std::cerr << "MKRTEST dest_nework: " << *dest_network << std::endl;
if(*is_broadcast) {
  std::cerr << "MKRTEST is broadcast" << std::endl;
} else {
  std::cerr << "MKRTEST is NOT broadcast" << std::endl;
  std::cerr << "MKRTEST dest_addr: ";
  for (auto c: *dest_addr) {
    std::cerr << (int)c;
  }
  std::cerr << std::endl;  
}
}
if (src_addr) {
  std::cerr << "MKRTEST src addr: ";
  for (auto c: *src_addr) {
    std::cerr << (int)c;
  }
  std::cerr << std::endl;    
}
if (hop_count) {
  std::cerr << "MKRTEST hop count: " << (int)*hop_count << std::endl;
}

    
  }
};

} // namespace {

void Inspector::eval(snort::Packet *p) {
std::cerr << "MKRTEST: --------------------(new msg)--------------------" << std::endl;
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
  const std::span<const uint8_t> data(p->data, p->dsize);
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
    Pegs::get<"packet_underflow">().inc();
    return;
  }

  if (msg_len < data.size()) {
    // udp packet contains data that isn't part of the message
    Pegs::get<"packet_extra_data">().inc();
    Pegs::get<"packet_extra_data_sum">().add(data.size() - msg_len);
  }

  // Decode NPDU
  bool ignore_version = settings->get<"ignore_version">();
  NPDUReader npdu_reader(data, read_pos, ignore_version);

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
