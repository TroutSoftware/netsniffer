#ifndef stream_splitter_7C3A91Ef
#define stream_splitter_7C3A91Ef

// Snort includes
#include <stream/stream_splitter.h>

// System includes

// Global includes

// Local includes

// Debug includes


namespace mqtt_plugin {

class StreamSplitter : public snort::StreamSplitter
{
  std::uint_fast8_t decode_shift=0;       // The number of
  uint32_t decoded_remaining_length = 0;  // The decoded value of the remaining length

  enum class State {
    initial,
    parsing_remaining_length,
    waiting_for_end
  } state = State::initial;

  // Called if the splitter detects invalid content
  Status scan_fail(snort::Packet*);

public:
  StreamSplitter(bool direction);
  ~StreamSplitter();

  // mqtt has its own definition of what a packet is
  bool is_paf() override { return true; }

  Status scan(
      snort::Packet*,
      const uint8_t* data,   // in order segment data as it arrives
      uint32_t len,          // length of data
      uint32_t flags,        // packet flags indicating direction of data
      uint32_t* fp           // flush point (offset) relative to data
      ) override;
};

} // namespace mqtt_plugin

#endif // #ifndef stream_splitter_7C3A91Ef
