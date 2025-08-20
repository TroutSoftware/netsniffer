#ifndef cache_59fa53e6
#define cache_59fa53e6

// Snort includes
#include <protocols/packet.h>

// System includes
#include <array>
#include <map>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

// Global includes

// Local includes

// Debug includes

namespace trout_netflow2 {

class CacheElement;
class Settings;

class Cache : public std::enable_shared_from_this<Cache> {
  std::shared_ptr<Settings> settings;

  class ServiceMap {
  public:
    using ServiceKey = uint32_t;

  private:
    std::mutex mutex; // Protects the service_map
    std::unordered_map<std::string, ServiceKey> service_map;

  public:
    ServiceMap();
    // Returns the ServiceKey corresponding to service_name
    ServiceKey get_add(const char *service_name);
    ServiceKey get_add(const std::string &service_name);
    std::size_t size();
  } service_map;

  struct CacheElement2 {
    struct ConstValues {
      uint32_t ipv4_src_addr = 0; // (8)  IPv4 source address
      uint32_t ipv4_dst_addr = 0; // (12) IPv4 destination address

      uint16_t l4_src_port = 0; // (7)  TCP/UDP source port
      uint16_t l4_dst_port = 0; // (11) TCP/UDP destination port

      std::array<uint8_t, 6> src_mac = {0, 0, 0,
                                        0, 0, 0}; // (56) Source MAC address
      std::array<uint8_t, 6> dst_mac = {0, 0, 0, 0,
                                        0, 0}; // (57) Destination MAC address
    };

    class ConstValuesComp {
    public:
      // Compares the key between the two elements
      bool operator()(const ConstValues &lhs, const ConstValues &rhs) const;
    };

    struct VolatileValues {
      std::mutex mutex;      // protects all memebers
      uint64_t in_bytes = 0; // (1)  Incoming counter of bytes (reset on dump)
      uint64_t in_pkts = 0;  // (2)  Incoming counter of packets (reset on dump)
      uint64_t out_bytes = 0; // (23) Outgoing counter of bytes (reset on dump)
      uint64_t out_pkts =
          0; // (24) Outgoing counter for packets (reset on dump)
      ServiceMap::ServiceKey service_key =
          0; // (25) Propritary service name key (NOT reset on dump)
      bool updated =
          false; // Set to true when a field is updated, false when dumped
    };
  };

  std::mutex
      mutex; // Protects the cache map, never take if you hold a value mutex
             // (it's ok to take a value mutex when holding the cache map thou)
  // Cache map contains the current cache, elements are removed when they are
  // logged, unless the shared_ptr count of the element is greater than 1
  // (meaning a handle is pointing to it)
  std::map<CacheElement2::ConstValues,
           std::shared_ptr<CacheElement2::VolatileValues>,
           CacheElement2::ConstValuesComp>
      cache;

  Cache(std::shared_ptr<Settings> settings);

  // Adds content of p to the cache, a new element will be created if needed
  std::shared_ptr<CacheElement2::VolatileValues> add_to_cache(snort::Packet *p);

public:
  // Using a Handle to add service names or packets to the cache is faster than
  // adding them without
  class Handle {
    // Friend is only one who can create us
    friend Cache;

    // Note, the shared_ptr is kept private as use the shared_ptr use_count to
    // know when the element can be removed from the cache - exposing the
    // shared_ptr could make this number unreliable if it was e.g. held as a
    // weak_ptr at some point, in which case we could have a race condition
    // between checking the count and geting a shared_ptr from the weak_ptr
    std::shared_ptr<CacheElement2::VolatileValues> data;
    std::shared_ptr<Cache> cache;

    Handle(std::shared_ptr<Cache> cache,
           std::shared_ptr<CacheElement2::VolatileValues>
               data); // Creates a new Handle pointing to data
  public:
    void add_sizes(snort::Packet *p); // Adds sizes from packet to handle (incl.
                                      // any service found)
    void add_service(const char *);   // Adds service to handle
  };

  std::unique_ptr<Handle> create(
      snort::Packet
          *p); // Creates a Handle from a snort packet (only adds the "const"
               // part of the packet ip, port, etc as they are part of the key)
  void add(snort::Packet *p); // Adds values from snort packet to cache (for use
                              // when there isn't a snort flow associated)

  static std::shared_ptr<Cache> create_cache(std::shared_ptr<Settings>);
};

} // namespace trout_netflow2

#endif // #ifndef cache_59fa53e6
