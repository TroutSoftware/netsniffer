
#include "flow_data.h"

namespace dhcp_option {

FlowData::FlowData(snort::Inspector *inspector)
    : snort::FlowData(get_id(), inspector) {}

unsigned FlowData::get_id() {
  static unsigned flow_data_id = snort::FlowData::create_flow_data_id();
  return flow_data_id;
}

bool FlowData::set(uint8_t type, size_t offset, size_t size) {
  return map.emplace(type, Entry{offset, size})
      .second; // Second will only be true if a new element was inserted
}

bool FlowData::get(uint8_t type, size_t &offset, size_t &size) {
  const auto entry = map.find(type);

  if (entry != map.end()) {
    offset = entry->second.offset;
    size = entry->second.size;
    return true;
  }

  return false;
}

} // namespace dhcp_option
