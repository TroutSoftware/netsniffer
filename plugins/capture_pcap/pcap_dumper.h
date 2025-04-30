#ifndef pcap_dumper_a25c9fdf
#define pcap_dumper_a25c9fdf

// Snort includes


// System includes
#include <pcap/pcap.h>
#include <string>

// Global includes

// Local includes

// Debug includes

namespace capture_pcap {

class PcapDumper {

public:
  PcapDumper(std::string base_name);  // Creates a dumper with base_name postfixed by

  void write_package(snort::Packet p); // Write p to the file
};

}
#endif // #ifndef pcap_dumper_a25c9fdf
