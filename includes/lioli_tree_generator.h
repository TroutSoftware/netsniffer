#ifndef tree_generator_2d7efb6e
#define tree_generator_2d7efb6e

// Snort includes
#include <protocols/eth.h>
#include <protocols/packet.h>
#include <sfip/sf_ip.h>

// System includes
#include <array>
#include <chrono>
#include <format>
#include <iomanip>
#include <sstream>

// Local includes
#include "lioli.h"

// Global includes
#include <testable_time.h>

namespace LioLi {

class TreeGenerators {

  static void append_MAC(std::stringstream &ss,
                         const std::array<uint8_t, 6> &mac) {

    ss << std::hex << std::setfill('0') << std::setw(2) << +(mac.at(0)) << ':'
       << std::setw(2) << +(mac.at(1)) << ':' << std::setw(2) << +(mac.at(2))
       << ':' << std::setw(2) << +(mac.at(3)) << ':' << std::setw(2)
       << +(mac.at(4)) << ':' << std::setw(2) << +(mac.at(5));
  }

  static void append_sf_ip(std::stringstream &ss, const snort::SfIp *sf_ip) {
    char ip_str[INET6_ADDRSTRLEN];

    sfip_ntop(sf_ip, ip_str, sizeof(ip_str));

    if (sf_ip->is_ip6()) {
      ss << '[' << ip_str << ']';
    } else {
      ss << ip_str;
    }
  }

public:
  static Tree timestamp(const char *txt, bool testmode = false) {
    Tree time(txt);
    time << std::format(
        "{:%FT%TZ}",
        Common::TestableTime::now<std::chrono::system_clock>(testmode));
    return time;
  }

  static Tree format_IP_MAC(const snort::Packet *p, const snort::Flow *flow,
                            bool is_src) {
    Tree addr("addr");
    std::stringstream ss;
    if (flow) {
      const snort::SfIp &sf_ip = (is_src ? flow->client_ip : flow->server_ip);
      const uint16_t port = (is_src ? flow->client_port : flow->server_port);

      append_sf_ip(ss, &sf_ip);

      addr << (Tree("ip") << ss.str()) << ":" << (Tree("port") << port);
    } else if (p->has_ip()) {
      const snort::SfIp *sf_ip =
          (is_src ? p->ptrs.ip_api.get_src() : p->ptrs.ip_api.get_dst());

      append_sf_ip(ss, sf_ip);

      addr << (Tree("ip") << ss.str());

      if (p->is_tcp() || p->is_udp()) {
        addr << ":" << (Tree("port") << (is_src ? p->ptrs.sp : p->ptrs.dp));
      } else {
        addr << ':' << '-';
      }
    } else {
      const snort::eth::EtherHdr *eh =
          ((p->proto_bits & PROTO_BIT__ETH) ? snort::layer::get_eth_layer(p)
                                            : nullptr);

      if (eh) {
        const auto mac = std::to_array<const uint8_t>(is_src ? eh->ether_src
                                                             : eh->ether_dst);
        append_MAC(ss, mac);

        addr << (Tree("mac") << ss.str());

      } else {
        // Nothing to add
      }
    }
    return addr;
  }
};

} // namespace LioLi

#endif // #ifndef tree_generator_2d7efb6e
