
// Snort includes
#include <protocols/packet.h>

// System includes

// Global includes

// Local includes
#include "cache.h"

// Debug includes

namespace snort {
class Packet;
};

namespace trout_netflow2 {

// Static factory function
std::shared_ptr<Cache> Cache::create_cache() {
  Cache *raw = new Cache();
  std::shared_ptr<Cache> shared(raw);

  return shared;
}

Cache::Cache(){};

void Cache::set_service_name(const char * /*name*/) {}

void Cache::update(snort::Packet * /*p*/) {}

void Cache::flow_terminated() {}

} // namespace trout_netflow2
