
// Snort includes

// System includes

// Global includes

// Local includes
#include "flow_data.h"

// Debug includes

namespace trout_netflow2 {

FlowData::FlowData(){};

FlowData::~FlowData() { cache->flow_terminated(); }

std::shared_ptr<Cache> FlowData::get_cache() { return cache; }

} // namespace trout_netflow2
