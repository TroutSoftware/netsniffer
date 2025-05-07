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

//int flow_count = 0;

struct CaptureFlow {
  std::optional<std::shared_ptr<PcapDumper>> dumper;
};

}

using FlowData = Common::FlowData<CaptureFlow>;


void Inspector::eval(snort::Packet * p) {

  FlowData *flow_data = (p->flow) ? FlowData::get_from_flow(p->flow) : nullptr;
  PcapDumper *pcap_dump = nullptr;

  if (!flow_data || !flow_data->dumper) {
    // TODO: Move filter to data structure
    if (!filter) {
      std::string filter_string("net 161.35.18.220");
  
      filter = std::unique_ptr<Filter>(new Filter(filter_string, module));
    }
    
    if(filter->match(p)) {
      std::cout << "MKRTEST Got a filter match!!!" << std::endl;

      if (!dumper) {
        //dumper = std::shared_ptr<PcapDumper>(new PcapDumper("base_name", module));
        dumper = std::make_shared<PcapDumper>("base_name", module);
      }

      if (flow_data) {
        std::cout << "MKRTEST: Made an forever choice to dump" << std::endl;
        flow_data->dumper.emplace(dumper);
      }
        
      pcap_dump = dumper.get();                
    } else if (flow_data) {
      // Filter didn't match
      std::cout << "MKRTEST: Made an forever choice to ignore" << std::endl;
      flow_data->dumper.emplace(std::shared_ptr<PcapDumper>());
    }
  } else if (flow_data->dumper) {
    if (*flow_data->dumper) {
      std::cout << "MKRTEST: Dump due to history" << std::endl;
    } else {
      std::cout << "MKRTEST: Ignore due to history" << std::endl;
    }
    
    pcap_dump = flow_data->dumper->get();
  }

  if (pcap_dump) {
    pcap_dump->queue_package(p);
  }
  
  module.get_peg_counts().pkg_processed++;

/*
  if(filter->match(p)) {
std::cout << "MKRTEST Got a filter match!!!" << std::endl;  
    dumper->queue_package(p);
  }
*/

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
