
#include "flow_data.h"

namespace NetFlow {

FlowData::FlowData() : snort::FlowData(get_id()) {}

unsigned FlowData::get_id() {
  static unsigned flow_data_id = snort::FlowData::create_flow_data_id();
  return flow_data_id;
}

FlowData *FlowData::get_from_flow(snort::Flow *flow) {
  assert(flow);

  FlowData *flow_data =
      dynamic_cast<FlowData *>(flow->get_flow_data(FlowData::get_id()));

  if (!flow_data) {
    flow_data = new FlowData();
    flow->set_flow_data(flow_data);
  }

  return flow_data;
}

void FlowData::add(std::string &&text) { queue.emplace(std::move(text)); }

void FlowData::add(LioLi::Tree &&tree) { queue.emplace(std::move(tree)); }

LioLi::Tree &operator<<(LioLi::Tree &tree, FlowData &flow_data) {

  while (!flow_data.queue.empty()) {
    if (std::holds_alternative<std::string>(flow_data.queue.front())) {
      tree << std::move(std::get<std::string>(flow_data.queue.front()));
    } else {
      tree << std::move(std::get<LioLi::Tree>(flow_data.queue.front()));
    }
    flow_data.queue.pop();
  }

  return tree;
}

} // namespace NetFlow
