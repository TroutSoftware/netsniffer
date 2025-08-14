#ifndef cache_element_091148c6
#define cache_element_091148c6

// Snort includes

// System includes
#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

// Global includes

// Local includes

// Debug includes

// We don't need to include the actual snort header here
namespace snort {
class Packet;
};

namespace trout_netflow2 {

class CacheElement {
  std::mutex mutex; // Protects all non-atomic members

  // TODO: Add time for create/last reset
  // TODO: Add time for last update
  // TODO: Could this be set by the worker thread exclusively, so it doesn't need the mutex?

  // Data that can be exported (Numbers in () are the RFC 3954 ID of the field)

  uint64_t in_bytes = 0;      // (1)  Incoming counter of bytes
  uint64_t in_pkts = 0;       // (2)  Incoming counter of packets
  uint64_t out_bytes = 0;     // (23) Outgoing counter of bytes
  uint64_t out_pkts = 0;      // (24) Outgoing counter for packets
  uint64_t trout_flow_id = 0; // (43) Unique ID of flow

  std::array<uint8_t, 6> src_mac = {0, 0, 0,
                                    0, 0, 0}; // (56) Source MAC address
  std::array<uint8_t, 6> dst_mac = {0, 0, 0,
                                    0, 0, 0}; // (57) Destination MAC address

  uint32_t ipv4_src_addr = 0; // (8)  IPv4 source address
  uint32_t ipv4_dst_addr = 0; // (12) IPv4 destination address

  uint16_t l4_src_port = 0; // (7)  TCP/UDP source port
  uint16_t l4_dst_port = 0; // (11) TCP/UDP destination port

  // uint8_t protocol = 0;  // (4)  IP protocol byte
  // uint8_t direction = 0; // (61) Flow direction

  enum class Status : uint8_t {
    undefined = 0,
    active = 1,
    terminated = 3,
  } trout_flow_status = Status::undefined;

  std::string service_name; // (25) Propritary service name

  // Internal

  bool data_updated = false; // Set to true if data has been changed since last emit

  bool first_pkt_handled = false; // Set to true after the first packet has been
                                  // handled (ip, port, etc has been set)

  CacheElement(); // Constructor is private, use factory functions to initialize
  CacheElement(const CacheElement &) = delete; // Don't allow copy constructors
  CacheElement &
  operator=(CacheElement &) = delete; // Don't allow assignment operators
public:
  // Factory function for cache
  static std::shared_ptr<CacheElement> create_cache_element();

  bool set_service_name(
      const char *name); // Sets the currently known service name for this flow

  bool update(snort::Packet *p);  // Returns true if the element changed state from not-updated to updated

  bool flow_terminated(); // Called by the flow data, set_service and update
                          // functions are illegal to call after this

  // Used as comparison operator
  bool operator()(const CacheElement &lhs, const CacheElement &rhs) const;

  std::string dump(uint16_t id);           // Dumps the data contained using id
  std::string dump_template(uint16_t id);  // Dumps the template using id
};

} // namespace trout_netflow2

#endif // #ifndef cache_element_091148c6
