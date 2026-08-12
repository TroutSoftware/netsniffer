
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes
#include <log/messages.h>
#include <protocols/packet.h>

// System includes
#include <span>

// Global includes

// Local includes
#include "flow_data.h"
#include "stream_splitter.h"

// Debug includes
#include <iostream>

namespace mqtt_plugin {

StreamSplitter::StreamSplitter(bool direction) : snort::StreamSplitter(direction) {
}

StreamSplitter::~StreamSplitter() {
}

StreamSplitter::Status StreamSplitter::scan_fail(snort::Packet*p) {
  if (p->flow) {
    p->flow->set_service(p, 0);
  } else {
    snort::WarningMessage("MQTT Stream splitter received a Packet without flow, and failed\n");
  }

  return ABORT;
}

StreamSplitter::Status StreamSplitter::scan(
      snort::Packet* p,
      const uint8_t* data,    // in order segment data as it arrives
      uint32_t len,          // length of data
      uint32_t /*flags*/,        // packet flags indicating direction of data
      uint32_t* fp           // flush point (offset) relative to data
      ) {
  assert(p);
  assert(data);
  assert(fp);

  PacketFlowData *flow_data = PacketFlowData::get_from_flow(p->flow);

  std::cerr << "MKRTEST: Splitter got flow " << flow_data->flow_id << " with " << len << " bytes" << std::endl;


  // For detailed description of the remaning length and terms,
  // see "2 MQTT Control Packet format" in the OASIS MQTT 5.0 standard
  std::span<const uint8_t> raw(data, len);
  uint32_t split_pos=0;

  for (const auto c : raw) {
    split_pos++;
    switch (state) {
      case State::initial:
        decode_shift=0;
        decoded_remaining_length=0;
        msg_type = static_cast<MsgType>(c >> 4);
        state = State::parsing_remaining_length;
        continue;

      case State::parsing_remaining_length:
        {
          if (decode_shift != 0 && c == 0) {
            // A zero must be encoded in a single byte, a zero at the end
            // is not allowed by the MQTT requirement that of encoding
            // must be minimal
            return scan_fail(p);
          }
          uint32_t temp = c;
          temp &= 0b0111'1111;  // We only need the 7 low bits
          decoded_remaining_length |= temp << decode_shift;

          if ((c & 0x1000'0000) == 0) {
            // We are at the end
            if (decoded_remaining_length) {
              state = State::waiting_for_end;

            // TODO: Make some sanity check on length here

              continue;
            } else {
              // There is no more data
              state = State::initial;
              *fp = split_pos;
              return FLUSH;
            }
          }

          decode_shift += 7;

          if(decode_shift > 7*4 ) {
            // MQTT doesn't allow more then 4 bytes to express the length
            return scan_fail(p);
          }
        }
        break;

      case State::waiting_for_end:
        decoded_remaining_length--;
        if (decoded_remaining_length <= len - split_pos) {
          // We have the data we need in the current buffer
          *fp = split_pos + decoded_remaining_length;

          state = State::initial;

          return FLUSH;
        }

        decoded_remaining_length -= (len - split_pos);

        return SEARCH;
    }
  }

  return SEARCH;
}

} // namespace mqtt_plugin
