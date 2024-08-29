
#include "flow_data.h"

namespace NetFlow {

FlowData::FlowData() : snort::FlowData(get_id()) {}

unsigned FlowData::get_id() {
  static unsigned flow_data_id = snort::FlowData::create_flow_data_id();
  return flow_data_id;
}

} // namespace NetFlow
