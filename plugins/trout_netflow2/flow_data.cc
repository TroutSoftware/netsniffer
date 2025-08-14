
// Snort includes

// System includes

// Global includes

// Local includes
#include "flow_data.h"

// Debug includes

namespace trout_netflow2 {

FlowData::FlowData(){};

FlowData::~FlowData() { cache_element->flow_terminated(); }

std::shared_ptr<CacheElement> FlowData::get_cache_element() const {
  return cache_element;
}

} // namespace trout_netflow2
