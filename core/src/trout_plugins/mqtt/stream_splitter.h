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
  unsigned splitter_instance;  // Debug code

  std::uint_fast8_t decode_shift=0;       // The number o
  uint32_t decoded_remaining_length = 0;          // The decoded value of the remaining length

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
#if 0
  const snort::StreamBuffer reassemble(
      snort::Flow*,
      unsigned total,        // total amount to flush (sum of iterations)
      unsigned offset,       // data offset from start of reassembly
      const uint8_t* data,   // data to reassemble
      unsigned len,          // length of data to process this iteration
      uint32_t flags,        // packet flags indicating pdu head and/or tail
      unsigned& copied       // actual data copied (1 <= copied <= len)
      ) override;
#endif
#if 0
    enum Status
    {
        ABORT,   // non-paf operation
        START,   // internal use only
        SEARCH,  // searching for next flush point
        FLUSH,   // flush at given offset
        LIMIT,   // flush to given offset upon reaching paf_max
        SKIP,    // skip ahead to given offset
        LIMITED, // previously did limit flush
        STOP     // stop paf scan loop
    };

    // scan(), finish(), reassemble() are called in this order:
    // (scan (reassemble)*)* finish (reassemble)*

    virtual Status scan(
        Packet*,
        const uint8_t* data,   // in order segment data as it arrives
        uint32_t len,          // length of data
        uint32_t flags,        // packet flags indicating direction of data
        uint32_t* fp           // flush point (offset) relative to data
        ) = 0;

    // finish indicates end of scanning
    // return false to discard any unflushed data
    virtual bool finish(Flow*) { return true; }
    virtual bool init_partial_flush(Flow*) { return false; }

    // the last call to reassemble() will be made with len == 0 if
    // finish() returned true as an opportunity for a final flush
    virtual const StreamBuffer reassemble(
        snort::Flow*,
        unsigned total,        // total amount to flush (sum of iterations)
        unsigned offset,       // data offset from start of reassembly
        const uint8_t* data,   // data to reassemble
        unsigned len,          // length of data to process this iteration
        uint32_t flags,        // packet flags indicating pdu head and/or tail
        unsigned& copied       // actual data copied (1 <= copied <= len)
        );

    virtual bool restart() { return false; }
    virtual bool sync_on_start() const { return false; }
    virtual bool is_paf() { return false; }
    virtual unsigned max(Flow* = nullptr);
    virtual void go_away() { delete this; }

    bool to_server() { return c2s; }
    bool to_client() { return !c2s; }

protected:
    StreamSplitter(bool b) : c2s(b) { }
    uint16_t get_flush_bucket_size();
    unsigned bytes_scanned = 0;
#endif

};

} // namespace mqtt_plugin

#endif // #ifndef stream_splitter_7C3A91Ef
