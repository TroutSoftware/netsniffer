
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
#include "stream_splitter.h"

// Debug includes
#include <iostream>

namespace mqtt_plugin {

StreamSplitter::StreamSplitter(bool direction) : snort::StreamSplitter(direction) {
  // DEBUG CODE
  static unsigned splitterNo = 0;
  splitter_instance = splitterNo++;

  std::cerr << "MKRTEST: (" << splitter_instance << ") StreamSplitter ctor(" << this << ")" << std::endl;

}

StreamSplitter::~StreamSplitter() {
  std::cerr << "MKRTEST: (" << splitter_instance << ") ~StreamSplitter dtor(" << this << ")" << std::endl;
}

StreamSplitter::Status StreamSplitter::scan_fail(snort::Packet*p) {
  std::cerr << "Scan_failed" << std::endl;
  if (p->flow) {
    p->flow->set_service(p, 0);
  } else {
    snort::WarningMessage("MQTT Stream splitter received a Packet without flow");
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


#if 1
  // For detailed description of the remaning length and terms,
  // see "2 MQTT Control Packet format" in the OASIS MQTT 5.0 standard

  std::span<const uint8_t> raw(data, len);
  uint32_t split_pos=0;

  for (const auto c : raw) {
    split_pos++;
    switch (state) {
      case State::initial:
std::cerr << "MKRTEST: (" << splitter_instance << ")  initial looking at a " << (unsigned)c << std::endl;
        decode_shift=0;
        decoded_remaining_length=0;
        state = State::parsing_remaining_length;
        continue;

      case State::parsing_remaining_length:
        {
std::cerr << "MKRTEST: (" << splitter_instance << ")  parsing length with a " << (unsigned)c << std::endl;
          if (decode_shift != 0 && c == 0) {
std::cerr << "MKRTEST: (" << splitter_instance << ")  parsing failed at " << (unsigned)c << std::endl;
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
std::cerr << "MKRTEST: (" << splitter_instance << ") found message with " << decoded_remaining_length << " bytes of var data" << std::endl;
              // TODO: Add sanity check for lenght vs type of message

              continue;
            } else {
               // There is no more data
          std::cerr << "MKRTEST: (" << splitter_instance << ")  Returning FLUSH " << (unsigned)split_pos
          <<   " len was " << len << std::endl;

               state = State::initial;
               *fp = split_pos;
               return FLUSH;
            }
          }

          decode_shift += 7;

          if(decode_shift > 7*4 ) {
std::cerr << "MKRTEST: (" << splitter_instance << ")  overflow found at " << (unsigned)c << std::endl;
            // MQTT doesn't allow more then 4 bytes to express the length
            return scan_fail(p);
          }
        }
        break;

      case State::waiting_for_end:
        if (--decoded_remaining_length == 0) {
          state = State::initial;
          *fp = split_pos;
std::cerr << "MKRTEST: (" << splitter_instance << ")  Returning FLUSH " << (unsigned)split_pos
          <<   " len was " << len << std::endl;
          return FLUSH;
        }
        continue;
    }
  }
std::cerr << "MKRTEST: (" << splitter_instance << ")  Came to the end " << std::endl;
  return SEARCH;
#endif
#if 0
if (state == State::initial)
{
  if (p->flow) {
    std::cerr << "MKRTEST: (" << splitter_instance << ") packet has flow, clearing service" << std::endl;
    p->flow->set_service(p, 0);
    return ABORT;
  } else {
    std::cerr << "MKRTEST: (" << splitter_instance << ") packet has no flow" << std::endl;
  }
}
//void set_service(Packet*, const char* new_service)

  std::cerr << "MKRTEST: (" << splitter_instance << ") scan called with len=" << len << " flags=" << flags << std::endl;
  *fp = len;
  return SEARCH;
#endif
}
#if 0
const snort::StreamBuffer StreamSplitter::reassemble(
    snort::Flow*,
    unsigned total,        // total amount to flush (sum of iterations)
    unsigned offset,       // data offset from start of reassembly
    const uint8_t* /*data*/,   // data to reassemble
    unsigned len,          // length of data to process this iteration
    uint32_t /*flags*/,        // packet flags indicating pdu head and/or tail
    unsigned& copied       // actual data copied (1 <= copied <= len)
    ) {
  std::cerr << "MKRTEST: (" << splitter_instance << ") reassemble called with total=" << total << " offeset=" << offset << " len=" << len << std::endl;

  copied = len;

/*
struct StreamBuffer
{
    const uint8_t* data;
    unsigned length;
};
*/
  return {new uint8_t[1024], 1024};


}
#endif

} // namespace mqtt_plugin
