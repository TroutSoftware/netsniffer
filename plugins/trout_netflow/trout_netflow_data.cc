
// Snort includes

// System includes
#include <cassert>

// Local includes
#include "lioli_tree_generator.h"
#include "trout_netflow.h"
#include "trout_netflow_data.h"

// Debug includes

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
  root << LioLi::TreeGenerators::timestamp("EndTime")
       << (LioLi::Tree("PacketDelta") << pkt_delta)
       << (LioLi::Tree("PayloadDelta") << payload_delta)
       << (LioLi::Tree("PacketAcc") << pkt_sum)
       << (LioLi::Tree("PayloadAcc") << payload_sum)
       << (LioLi::Tree("PacketSum") << pkt_sum)
       << (LioLi::Tree("PayloadSum") << payload_sum);

  logger->log(std::move(root));
}

void FlowData::process(snort::Packet *pkt) {
  assert(pkt);

  auto now = std::chrono::steady_clock::now();

  if (first_pkt) {
    first_pkt_time = now;
    delta_pkt_time = now;
    root << LioLi::TreeGenerators::timestamp("Timestamp");
    // format_IP_MAC handles a null flow
    root << (LioLi::Tree("principal")
             << LioLi::TreeGenerators::format_IP_MAC(pkt, pkt->flow, true));

    root << (LioLi::Tree("endpoint")
             << LioLi::TreeGenerators::format_IP_MAC(pkt, pkt->flow, false));

    first_pkt = false;
  }

  pkt_sum += pkt->pktlen;
  payload_sum += pkt->dsize;

  pkt_delta += pkt->pktlen;
  payload_delta += pkt->dsize;

  s_peg_counts.pkt_size += pkt->pktlen;
  s_peg_counts.payload_size += pkt->dsize;

  if (pkt_delta > (pkt_sum >> 3) ||
      (pkt_delta > 0 &&
       std::chrono::duration_cast<std::chrono::minutes>(now - delta_pkt_time)
               .count() > 10)) {
    dump_delta();
  }
}

void FlowData::dump_delta() {
  auto now = std::chrono::steady_clock::now();
  delta_pkt_time = now;

  auto tmp = root;
  tmp << LioLi::TreeGenerators::timestamp("DeltaTime")
      << (LioLi::Tree("PacketDelta") << pkt_delta)
      << (LioLi::Tree("PayloadDelta") << payload_delta)
      << (LioLi::Tree("PacketAcc") << pkt_sum)
      << (LioLi::Tree("PayloadAcc") << payload_sum);

  pkt_delta = 0;
  payload_delta = 0;

  logger->log(std::move(tmp));
}

void FlowData::set_service_name(const char *name) {
  root << (LioLi::Tree("service") << std::string(name));
  dump_delta();
}

} // namespace trout_netflow
