
// Snort includes
#include <protocols/eth.h>
#include <protocols/packet.h>

// System includes

// Global includes

// Local includes
#include "cache_element.h"
#include "pegs.h"

// Debug includes

namespace snort {
class Packet;
};

namespace {
uint64_t generate_flow_id() {
  static uint64_t id = 0;
  id++;
  return id;
}

} // namespace

namespace trout_netflow2 {

// Static factory function
std::shared_ptr<CacheElement> CacheElement::create_cache_element() {
  // We use new instead of std::make_shared as ctor is private
  std::shared_ptr<CacheElement> shared(new CacheElement());

  return shared;
}

CacheElement::CacheElement() { trout_flow_id = generate_flow_id(); };

void CacheElement::set_service_name(const char * /*name*/) {}

void CacheElement::update(snort::Packet *p) {
  assert(p);
  assert(
      Status::terminated !=
      trout_flow_status); // TODO: Evaluate if this should be a warning instead

  std::scoped_lock lock(mutex);

  if (Status::undefined == trout_flow_status) {
    first_pkt_handled = true;

    const snort::eth::EtherHdr *eh =
        ((p->proto_bits & PROTO_BIT__ETH) ? snort::layer::get_eth_layer(p)
                                          : nullptr);

    if (eh) {
      src_mac = std::to_array<const uint8_t>(eh->ether_src);
      dst_mac = std::to_array<const uint8_t>(eh->ether_dst);
    }

    if (p->has_ip()) {
      if (p->ptrs.ip_api.get_src()->is_ip4()) {
        ipv4_src_addr = p->ptrs.ip_api.get_src()->get_ip4_value();
      } else {
        // TODO: Handle IPv6 for src
      }
      if (p->ptrs.ip_api.get_dst()->is_ip4()) {
        ipv4_dst_addr = p->ptrs.ip_api.get_dst()->get_ip4_value();
      } else {
        // TODO: Handle IPv6 for dst
      }

      if (p->is_tcp() || p->is_udp()) {
        l4_src_port = p->ptrs.sp;
        l4_dst_port = p->ptrs.dp;
      }
    }
    trout_flow_status = Status::active;
  }

  if (p->is_from_client()) {
    in_pkts++;
    in_bytes += p->pktlen;
  } else {
    out_pkts++;
    out_bytes += p->pktlen;
  }

  Pegs::s_peg_counts.total_bytes += p->pktlen;
}

void CacheElement::flow_terminated() { trout_flow_status = Status::terminated; }

} // namespace trout_netflow2
