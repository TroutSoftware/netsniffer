// Snort includes
#include <detection/detection_engine.h>
#include <protocols/icmp4.h>
#include <protocols/packet.h>

// System includes

// Global includes
#include <lioli_tree_generator.h>
#include <trout_gid.h>

// Local includes
#include "gid_sid.h"
#include "inspector.h"
#include "module.h"
#include "pegs.h"

// Debug includes
#include <iostream>

namespace icmp_logger {

namespace {
const uint8_t null_hw_adr[6] = {0, 0, 0, 0, 0, 0};
const uint8_t broadcast_hw_adr[6]{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

} // namespace

void Inspector::eval(snort::Packet *p) {
  // If we don't get arp, then something is wrong
  assert(p && p->is_icmp());

  Pegs::s_peg_counts.icmp_packets++;

  if (p->ptrs.icmph) {
    switch (p->ptrs.icmph->type) {
    case snort::icmp::DEST_UNREACH: {
      log_unreachable(*(p->ptrs.icmph));
    } break;

    case snort::icmp::ECHOREPLY:
    case snort::icmp::SOURCE_QUENCH:
    case snort::icmp::REDIRECT:
    case snort::icmp::ECHO_4:
    case snort::icmp::ROUTER_ADVERTISE:
    case snort::icmp::ROUTER_SOLICIT:
    case snort::icmp::TIME_EXCEEDED:
    case snort::icmp::PARAMETERPROB:
    case snort::icmp::TIMESTAMP:
    case snort::icmp::TIMESTAMPREPLY:
    case snort::icmp::INFO_REQUEST:
    case snort::icmp::INFO_REPLY:
    case snort::icmp::ADDRESS:
    case snort::icmp::ADDRESSREPLY:
      break;
    }
  }
}

void Inspector::log_unreachable(const snort::icmp::ICMPHdr &hdr) {

  LioLi::Tree root("$");

  root << (LioLi::Tree("log") << "ICMP unreachable");

  union IP {
    uint32_t ip32;
    uint8_t ip4[4];
  } ip;

  ip.ip32 = ((snort::ip::IP4Hdr *)((void *)&hdr.icmp_dun))->ip_src;
  auto src_ip = std::to_array<const uint8_t>(ip.ip4);
  ip.ip32 = ((snort::ip::IP4Hdr *)((void *)&hdr.icmp_dun))->ip_dst;
  auto dst_ip = std::to_array<const uint8_t>(ip.ip4);

  root << (LioLi::Tree("src") << LioLi::TreeGenerators::format_IPv4(src_ip));
  root << (LioLi::Tree("dst") << LioLi::TreeGenerators::format_IPv4(dst_ip));
  root << (LioLi::Tree("sid") << icmp_logger_destination_unreachable);
  root << (LioLi::Tree("gid") << icmp_logger_gid);
  root << (LioLi::Tree("rev") << 0);

  settings->get_logger() << std::move(root);

  snort::DetectionEngine::queue_event(icmp_logger_gid,
                                      icmp_logger_destination_unreachable);
}

Inspector::Inspector(Module *module) : settings(module->get_settings()) {}

Inspector::~Inspector() {}

snort::Inspector *Inspector::ctor(snort::Module *module) {
  return new Inspector(dynamic_cast<Module *>(module));
}

} // namespace icmp_logger
