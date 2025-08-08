// Snort includes
#include <protocols/packet.h>

// System includes

// Global includes

// Local includes
#include "cache_element.h"
#include "flow_data.h"
#include "inspector.h"
#include "module.h"
#include "pegs.h"

// Debug includes

namespace trout_netflow2 {

void Inspector::eval(snort::Packet *p) {
  assert(p);

  Pegs::s_peg_counts.pkts_seen++;

  if (p->flow) {
    PacketFlowData *flow_data = PacketFlowData::get_from_flow(
        p->flow, [](FlowData &) { Pegs::s_peg_counts.flows_seen++; });
    flow_data->get_cache_element()->update(p);
  } else {
    FlowData flow_data;
    Pegs::s_peg_counts.pkts_without_flow++;
    flow_data.get_cache_element()->update(p);
  }
}

Inspector::Inspector(Module *module) : settings(module->get_settings()) {}

Inspector::~Inspector() {}

snort::Inspector *Inspector::ctor(snort::Module *module) {
  return new Inspector(dynamic_cast<Module *>(module));
}

void Inspector::dtor(snort::Inspector *p) { delete p; }

} // namespace trout_netflow2
