// Snort includes
#include <log/messages.h>
#include <protocols/packet.h>
#include <stream/stream_splitter.h>

// System includes
#include <mutex>
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

int flow_count = 0;

class CaptureFlow {
public:
  CaptureFlow() {

  }

  ~CaptureFlow() {

  }
};

}

using FlowData = Common::FlowData<CaptureFlow>;


void Inspector::eval(snort::Packet * p) {

//std::cout << "MKRTEST: Got package";

//if (p->flow) std::cout << " with flow";

//std::cout << std::endl;
  FlowData *flow_data = (p->flow) ? FlowData::get_from_flow(p->flow) : nullptr;

  if (flow_data) {
    
  }

  if (!filter) {
    std::string filter_string("net 140.82.121.4");

    filter = std::unique_ptr<Filter>(new Filter(filter_string, module));
  }
  
  module.get_peg_counts().pkg_processed++;

  if(filter->match(p)) {
std::cout << "MKRTEST Got a filter match!!!" << std::endl;  

  }


}

Inspector::Inspector(Module &module) : module(module) {
  assert(&module);
};

Inspector::~Inspector() {
}


snort::Inspector *Inspector::ctor(snort::Module *module) {
  return new Inspector(*dynamic_cast<Module *>(module));
}

void Inspector::dtor(snort::Inspector *p) {
  delete dynamic_cast<Inspector *>(p);
}

} // namespace capture_pcap
