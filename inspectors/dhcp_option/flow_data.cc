
#include "flow_data.h"

namespace dhcp_option {

FlowData::FlowData(snort::Inspector *inspector)
    : snort::FlowData(get_id(), inspector) {}

unsigned FlowData::get_id() {
  static unsigned flow_data_id = snort::FlowData::create_flow_data_id();
  return flow_data_id;
}

} // namespace dhcp_option
