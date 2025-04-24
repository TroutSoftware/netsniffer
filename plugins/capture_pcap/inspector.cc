// Snort includes
#include <log/messages.h>
#include <packet_io/sfdaq.h>
#include <protocols/packet.h>
#include <stream/stream_splitter.h>

// System includes
#include <mutex>
#include <pcap/pcap.h>
#include <string>

// Global includes
#include <flow_data.h>


// Local includes
#include "inspector.h"
#include "module.h"

// Debug includes
#include <iostream>

// TODO:  We currently DO NOT call pcap_init(...), snort is using libpcap
//        but doesn't seem to be calling it, and calling it might
//        influence the behavior of libpcap, investigate....

namespace capture_pcap {
namespace {

class Filter {
  Module &module;
  const std::string filter_string;      // Clear text filter
  bool compiled_valid = false;   // Set to true if the compiled bpf program is valid
  struct bpf_program compiled;   // Compiled filter
  
  // The following function is copied from snorts packet_capture plugin
  int get_dlt()
  {
    int dlt = snort::SFDAQ::get_base_protocol();
    if (dlt == DLT_USER1)
        return DLT_EN10MB;
    return dlt;
  }
  
public:
  Filter(std::string &filter_string, Module &module) : module(module), filter_string(filter_string) {
    pcap_t *dead = pcap_open_dead(get_dlt(), module.get_settings().snaplen);
    if(pcap_compile(dead, &compiled, filter_string.c_str(), module.get_settings().optimize_filter, PCAP_NETMASK_UNKNOWN)) {      
      snort::ErrorMessage("ERROR: pcap compile returns \"%s\" when given \"%s\" as input",
                          pcap_geterr(dead), filter_string.c_str());
      
    } else {
      compiled_valid = true;
      module.get_peg_counts().compiled_filters++;
    }
  }

  ~Filter() {
    // Clean up
    if(compiled_valid) {
      pcap_freecode(&compiled);
      compiled_valid = false;
    }
  }

  bool is_valid() {
    return compiled_valid;
  }
};

class CaptureFlow {
  
};

using FlowData = Common::FlowData<CaptureFlow>;


} // namespace


void Inspector::eval(snort::Packet * p) {
  module.get_peg_counts().pkg_processed++;
std::cout << "MKRTEST: Got package";

if (p->flow) std::cout << " with flow";

std::cout << std::endl;
}

Inspector::~Inspector() {}


snort::Inspector *Inspector::ctor(snort::Module *module) {
  return new Inspector(*dynamic_cast<Module *>(module));
}

void Inspector::dtor(snort::Inspector *p) {
  delete dynamic_cast<Inspector *>(p);
}

} // namespace capture_pcap
