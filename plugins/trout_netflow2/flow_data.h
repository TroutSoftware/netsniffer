#ifndef flow_data_5e04bb05
#define flow_data_5e04bb05

// Snort includes

// System includes
#include <memory>

// Global includes
#include <flow_data.h>

// Local includes
#include "cache.h"
// #include "cache_element.h"

// Debug includes

namespace trout_netflow2 {

struct FlowData {
  std::unique_ptr<Cache::Handle> handle;
};

using PacketFlowData = Common::FlowData<FlowData>;

} // namespace trout_netflow2

#endif // #ifndef flow_data_5e04bb05
