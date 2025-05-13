
#ifndef filter_e39dc916
#define filter_e39dc916

// Snort includes
#include <protocols/packet.h>

// System includes
#include <pcap/pcap.h>

// Global includes

// Local includes
#include "module.h"
#include "settings.h"

// Debug includes

namespace capture_pcap {

class Filter {
  std::shared_ptr<Settings> settings;
  PegCounts &pegs;

  const std::string filter_string; // Clear text filter
  bool compiled_valid =
      false; // Set to true if the compiled bpf program is valid
  struct bpf_program compiled; // Compiled filter

  void compile();

public:
  Filter(std::string &filter_string, Module &module);
  Filter(std::string &&filter_string, std::shared_ptr<Settings> settings,
         PegCounts &pegs);

  ~Filter();

  bool is_valid();

  bool
  match(snort::Packet *p); // Runs filter on p, invalid filter will return false
};

} // namespace capture_pcap

#endif // #ifndef filter_e39dc916
