
// Snort includes

// System includes
#include <cassert>

// Local includes
#include "lioli_tree_generator.h"
#include "trout_netflow.private.h"
#include "trout_netflow_data.h"

// Global includes
#include <testable_time.h>

// Debug includes

namespace trout_netflow {

FlowData::FlowData(Settings &settings)
    : snort::FlowData(get_id()), settings(settings) {}

unsigned FlowData::get_id() {
  static unsigned flow_data_id = snort::FlowData::create_flow_data_id();
  return flow_data_id;
}

FlowData *FlowData::get_from_flow(snort::Flow *flow, Settings &settings) {
  assert(flow);

  FlowData *flow_data =
      dynamic_cast<FlowData *>(flow->get_flow_data(FlowData::get_id()));

  if (!flow_data) {

    flow_data = new FlowData(settings);
    flow->set_flow_data(flow_data);
  }

  return flow_data;
}

FlowData::~FlowData() {
  auto tmp = gen_delta();
  tmp << LioLi::TreeGenerators::timestamp("end_time", settings.testmode);
  settings.get_logger() << std::move(tmp);
}

void FlowData::process(snort::Packet *pkt) {
  assert(pkt);

  // Note, this uses steady_clock instead of system_clock to ensure delta times
  // are correct
  auto now =
      Common::TestableTime::now<std::chrono::steady_clock>(settings.testmode);

  if (first_pkt) {
    first_pkt_time = now;
    delta_pkt_time = now;

    root << LioLi::TreeGenerators::timestamp("start_time", settings.testmode);

    // format_IP_MAC handles a null flow
    root << (LioLi::Tree("principal")
             << LioLi::TreeGenerators::format_IP_MAC(pkt, pkt->flow, true));

    root << (LioLi::Tree("endpoint")
             << LioLi::TreeGenerators::format_IP_MAC(pkt, pkt->flow, false));

    first_pkt = false;
  }

  PP pp(pkt->pktlen, pkt->dsize);

  acc += pp;
  delta += pp;

  s_peg_counts.pkt_size += pkt->pktlen;
  s_peg_counts.payload_size += pkt->dsize;

  if (delta.is_significant_of(acc) ||
      (delta &&
       std::chrono::duration_cast<std::chrono::minutes>(now - delta_pkt_time)
               .count() > 10)) {
    dump_delta();
  }
}

LioLi::Tree FlowData::gen_delta() {
  auto now = std::chrono::steady_clock::now();
  delta_pkt_time = now;

  auto tmp = root;
  auto delta_root = delta.gen_tree();
  delta_root << LioLi::TreeGenerators::timestamp("time", settings.testmode);
  tmp << delta_root << acc.gen_tree();

  delta.clear();

  return tmp;
}

void FlowData::dump_delta() { settings.get_logger() << gen_delta(); }

void FlowData::set_service_name(const char *name) {
  root << (LioLi::Tree("service") << std::string(name));
  dump_delta();
}

} // namespace trout_netflow
