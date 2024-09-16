
// Snort includes

// System includes
#include <cassert>

// Local includes
#include "lioli_tree_generator.h"
#include "trout_netflow_data.h"

namespace trout_netflow {

FlowData::FlowData(std::shared_ptr<LioLi::LogLioLiTree> logger)
    : snort::FlowData(get_id()), logger(logger) {}

unsigned FlowData::get_id() {
  static unsigned flow_data_id = snort::FlowData::create_flow_data_id();
  return flow_data_id;
}

FlowData *FlowData::get_from_flow(snort::Flow *flow,
                                  std::shared_ptr<LioLi::LogLioLiTree> logger) {
  assert(flow);

  FlowData *flow_data =
      dynamic_cast<FlowData *>(flow->get_flow_data(FlowData::get_id()));

  if (!flow_data) {
    flow_data = new FlowData(logger);
    flow->set_flow_data(flow_data);
  }

  return flow_data;
}

FlowData::~FlowData() {
  root << (LioLi::Tree("PacketSum") << pkt_sum)
       << (LioLi::Tree("PayloadSum") << payload_sum);

  logger->log(std::move(root));
  /*
    root << (LioLi::Tree(type) << msg);

    // format_IP_MAC handles a null flow
    root << (LioLi::Tree("principal")
             << LioLi::TreeGenerators::format_IP_MAC(pkt, pkt->flow, true));
  */
}

void FlowData::process(snort::Packet *pkt) {
  assert(pkt);

  pkt_sum += pkt->pktlen;
  payload_sum += pkt->dsize;

  if (first_pkt) {
    // format_IP_MAC handles a null flow
    root << (LioLi::Tree("principal")
             << LioLi::TreeGenerators::format_IP_MAC(pkt, pkt->flow, true));

    root << (LioLi::Tree("endpoint")
             << LioLi::TreeGenerators::format_IP_MAC(pkt, pkt->flow, false));

    first_pkt = false;
  }
}

void FlowData::set_service_name(const char *name) {
  root << (LioLi::Tree("service") << std::string(name));
}

} // namespace trout_netflow
