
// Snort includes
#include <protocols/eth.h>

// System includes

// Global includes

// Local includes
#include "cache.h"
#include "cache_element.h"
#include "pegs.h"
#include "settings.h"

// Debug includes

namespace trout_netflow2 {

/*
void Cache::add(std::shared_ptr<CacheElement> ce) {
  std::scoped_lock lock(mutex);

  // Check our cache has space for the new element
  if (data.size() >= settings->cache_size) {
    log();  // A log will remove any terminated elements

    // Se if it helped, otherwise make room
    if (data.size() >= settings->cache_size) {
      remove_random_element();  // We need to remove the element in an
unpredictable way
    }
  };

  data.push_back(ce);
}

void Cache::log() {

}

void Cache::remove_random_element() {
  // TODO: Fill out
}
*/
// ------------- New stuff -----------

Cache::Cache(std::shared_ptr<Settings> settings) : settings(settings) {
  assert(settings);
  // data.reserve(settings->cache_size);
}

std::shared_ptr<Cache> Cache::create_cache(std::shared_ptr<Settings> settings) {
  std::shared_ptr<Cache> cache(new Cache(settings));

  return cache;
}

Cache::ServiceMap::ServiceMap() {
  std::string unknown("[unknown]");
  get_add(unknown);
}

Cache::ServiceMap::ServiceKey
Cache::ServiceMap::get_add(const char *service_name) {
  std::scoped_lock lock(mutex);
  return (service_map.emplace(service_name, service_map.size()).first)->second;
}

Cache::ServiceMap::ServiceKey
Cache::ServiceMap::get_add(const std::string &service_name) {
  return get_add(service_name.c_str());
}
/*
Cache::ServiceMap::ServiceKey Cache::ServiceMap::get_add(std::string
&service_name) { std::scoped_lock lock(mutex); return
(service_map.emplace(service_name, service_map.size()).first)->second;
}
*/
bool Cache::CacheElement2::ConstValuesComp::operator()(
    const Cache::CacheElement2::ConstValues &lhs,
    const Cache::CacheElement2::ConstValues &rhs) const {
  return lhs.ipv4_src_addr < rhs.ipv4_src_addr ||
         (lhs.ipv4_src_addr == rhs.ipv4_src_addr &&
          (lhs.ipv4_dst_addr < rhs.ipv4_dst_addr ||
           (lhs.ipv4_dst_addr == rhs.ipv4_dst_addr &&
            (lhs.l4_src_port < rhs.l4_src_port ||
             (lhs.l4_src_port == rhs.l4_src_port &&
              (lhs.l4_dst_port < rhs.l4_dst_port ||
               (lhs.l4_dst_port == rhs.l4_dst_port &&
                ((lhs.src_mac <=> rhs.src_mac) < 0 ||
                 ((lhs.src_mac <=> rhs.src_mac) == 0 &&
                  ((lhs.dst_mac <=> rhs.dst_mac) < 0))))))))));
};

Cache::Handle::Handle(std::shared_ptr<Cache> cache,
                      std::shared_ptr<CacheElement2::VolatileValues> data)
    : data(data), cache(cache) {
  assert(cache);
  assert(data);
}

void Cache::Handle::add_sizes(snort::Packet *p) {
  assert(p);
  std::scoped_lock lock(data->mutex);
  if (p->is_from_client()) {
    data->in_pkts++;
    data->in_bytes += p->pktlen;
  } else {
    data->out_pkts++;
    data->out_bytes += p->pktlen;
  }

  Pegs::s_peg_counts.total_bytes += p->pktlen;
}

void Cache::Handle::add_service(std::string &s) {
  ServiceMap::ServiceKey key = cache->service_map.get_add(s);

  std::scoped_lock lock(data->mutex);
  data->service_key = key;
}

void Cache::add(snort::Packet *p) {
  // The add is the same as create, just discarding the handle
  create(p);
}

std::unique_ptr<Cache::Handle> Cache::create(snort::Packet *p) {
  CacheElement2::ConstValues key;

  const snort::eth::EtherHdr *eh =
      ((p->proto_bits & PROTO_BIT__ETH) ? snort::layer::get_eth_layer(p)
                                        : nullptr);

  if (eh) {
    key.src_mac = std::to_array(eh->ether_src);
    key.dst_mac = std::to_array(eh->ether_dst);
  }

  if (p->has_ip()) {
    if (p->ptrs.ip_api.get_src()->is_ip4()) {
      key.ipv4_src_addr = p->ptrs.ip_api.get_src()->get_ip4_value();
    } else {
      // TODO: Handle IPv6 for src
    }
    if (p->ptrs.ip_api.get_dst()->is_ip4()) {
      key.ipv4_dst_addr = p->ptrs.ip_api.get_dst()->get_ip4_value();
    } else {
      // TODO: Handle IPv6 for dst
    }

    if (p->is_tcp() || p->is_udp()) {
      key.l4_src_port = p->ptrs.sp;
      key.l4_dst_port = p->ptrs.dp;
    }
  }

  // We don't need the lock until this point
  std::scoped_lock cache_lock(mutex);

  // TODO: check size of cache vs settings->cache_size and make space if needed
  auto itr = cache.try_emplace(key, nullptr).first;

  if (!itr->second) {
    itr->second = std::make_shared<CacheElement2::VolatileValues>();
  }

  std::scoped_lock value_lock(itr->second->mutex);

  if (p->is_from_client()) {
    itr->second->in_pkts++;
    itr->second->in_bytes += p->pktlen;
  } else {
    itr->second->out_pkts++;
    itr->second->out_bytes += p->pktlen;
  }

  if (p->flow && p->flow->service) {
    itr->second->service_key = service_map.get_add(p->flow->service);
  }

  itr->second->updated = true;
}

/*
  Handle(std::shared_ptr<Cache> cache,
  std::shared_ptr<CacheElement2::VolatileValues> data);
    std::shared_ptr<CacheElement2::VolatileValues> data;

    Handle(std::shared_ptr<CacheElement2::VolatileValues> *data);       //
  Creates a new Handle pointing to data

  public:
    void add_sizes(snort::Packet *p);   // Adds sizes from packet to handle
  (incl. any service found) void add_service(std::string &s);    // Adds service
  to handle
*/
} // namespace trout_netflow2
