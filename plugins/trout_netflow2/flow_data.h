#ifndef flow_data_5e04bb05
#define flow_data_5e04bb05

// Snort includes

// System includes
#include <memory>

// Global includes
#include <flow_data.h>

// Local includes
#include "cache.h"

// Debug includes

namespace trout_netflow2 {

class FlowData {
  std::shared_ptr<Cache> cache = Cache::create_cache();

public:
  FlowData();
  ~FlowData();
  std::shared_ptr<Cache> get_cache();
};

using PacketFlowData = Common::FlowData<FlowData>;

} // namespace trout_netflow2

#endif // #ifndef flow_data_5e04bb05
