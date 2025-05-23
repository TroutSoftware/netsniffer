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

// TODO:  We currently DO NOT call pcap_init(...), snort is using libpcap
//        but doesn't seem to be calling it, and calling it might
//        influence the behavior of libpcap, investigate....

namespace capture_pcap {
namespace {

struct CaptureFlow {
  std::optional<std::shared_ptr<PcapDumper>> dumper;
};

} // namespace

using FlowData = Common::FlowData<CaptureFlow>;

void Inspector::eval(snort::Packet *p) {
  assert(p);

  FlowData *flow_data = (p->flow) ? FlowData::get_from_flow(p->flow) : nullptr;
  std::shared_ptr<PcapDumper> pcap_dump;

  if (!flow_data || !flow_data->dumper) {
    for (auto &item : settings->map) {
      if (item->ip) {
        if ((!p->has_ip() ||
             !((p->ptrs.ip_api.get_src()->is_ip4() &&
                *item->ip == p->ptrs.ip_api.get_src()->get_ip4_value()) ||
               (p->ptrs.ip_api.get_dst()->is_ip4() &&
                *item->ip == p->ptrs.ip_api.get_dst()->get_ip4_value())))) {
          pegs.ip_hint_mismatch++;
          continue;
        }
        pegs.ip_hint_match++;
      }

      if (item->port) {
        if ((!p->has_ip() ||
             (*item->port != p->ptrs.sp && *item->port != p->ptrs.dp))) {
          pegs.port_hint_mismatch++;
          continue;
        }
        pegs.port_hint_match++;
      }

      assert(
          item->filter); // Something went horrible wrong if there is no filter

      bool log_pkg = item->filter->match(p);

      if (log_pkg) {
        pcap_dump = item->dumper;
        break; // We found something, no need to continue loop
      }
    }

    if (flow_data) {
      pegs.pkg_flow_verdict++;
      flow_data->dumper = pcap_dump;
    } else {
      pegs.pkg_no_flow_verdict++;
    }

  } else {
    pcap_dump = flow_data->dumper.value(); //->get();
  }

  if (pcap_dump) {
    pcap_dump->queue_package(p);
  }

  pegs.pkg_processed++;
}

Inspector::Inspector(Module &module)
    : settings(module.get_settings()), pegs(module.get_peg_counts()){

                                       };

Inspector::~Inspector() {}

snort::Inspector *Inspector::ctor(snort::Module *module) {
  return new Inspector(*dynamic_cast<Module *>(module));
}

void Inspector::dtor(snort::Inspector *p) {
  delete dynamic_cast<Inspector *>(p);
}

} // namespace capture_pcap
