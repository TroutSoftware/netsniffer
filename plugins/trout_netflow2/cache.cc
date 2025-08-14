
// Snort includes

// System includes

// Global includes

// Local includes
#include "cache.h"
#include "cache_element.h"
#include "settings.h"

// Debug includes

namespace trout_netflow2 {

Cache::Cache(std::shared_ptr<Settings> settings) : settings(settings) {
  data.reserve(settings->cache_size);
}

void Cache::add(std::shared_ptr<CacheElement> ce) {
  std::scoped_lock lock(mutex);

  // Check our cache has space for the new element
  if (data.size() >= settings->cache_size) {
    log();  // A log will remove any terminated elements

    // Se if it helped, otherwise make room
    if (data.size() >= settings->cache_size) {
      remove_random_element();  // We need to remove the element in an unpredictable way
    }
  };

  data.push_back(ce);
}

void Cache::log() {

}

void Cache::remove_random_element() {
  // TODO: Fill out
}

Cache::ServiceMap::ServiceKey Cache::ServiceMap::get_add(std::string service_name) {
  std::scoped_lock lock(mutex);
  return (service_map.emplace(service_name, service_map.size()).first)->second;
}

bool Cache::CacheElement2::ConstValuesComp::operator()(const Cache::CacheElement2::ConstValues &lhs, const Cache::CacheElement2::ConstValues &rhs) const {
  return lhs.ipv4_src_addr < rhs.ipv4_src_addr || (lhs.ipv4_src_addr == rhs.ipv4_src_addr && (
         lhs.ipv4_dst_addr < rhs.ipv4_dst_addr || (lhs.ipv4_dst_addr == rhs.ipv4_dst_addr && (
         lhs.l4_src_port   < rhs.l4_src_port   || (lhs.l4_src_port   == rhs.l4_src_port   && (
         lhs.l4_dst_port   < rhs.l4_dst_port   || (lhs.l4_dst_port   == rhs.l4_dst_port   && (
         (lhs.src_mac <=> rhs.src_mac) < 0     || ((lhs.src_mac <=> rhs.src_mac) == 0     && (
         (lhs.dst_mac <=> rhs.dst_mac) < 0))))))))));
};


} // namespace trout_netflow2
