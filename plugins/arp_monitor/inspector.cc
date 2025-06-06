// Snort includes
#include <cstdint> // This is needed here as protocols/apr.h is depending on it

// #include <log/messages.h>
#include <protocols/arp.h>
#include <protocols/packet.h>

// System includes

// Global includes
#include <algorithm>

// Local includes
#include "inspector.h"
#include "pegs.h"

// Debug includes
#include <iostream>

namespace arp_monitor {

#if 0
namespace snort
{
namespace arp
{

struct ARPHdr
{
    uint16_t ar_hrd;       /* format of hardware address   */
    uint16_t ar_pro;       /* format of protocol address   */
    uint8_t ar_hln;        /* length of hardware address   */
    uint8_t ar_pln;        /* length of protocol address   */
    uint16_t ar_op;        /* ARP opcode (command)         */
};

struct EtherARP
{
    ARPHdr ea_hdr;      /* fixed-size header */
    uint8_t arp_sha[6];    /* sender hardware address */
    union
    {
        uint8_t arp_spa[4];    /* sender protocol address */
        uint32_t arp_spa32;
    };
    uint8_t arp_tha[6];    /* target hardware address */
    uint8_t arp_tpa[4];    /* target protocol address */
} __attribute__((__packed__));

constexpr uint16_t ETHERARP_HDR_LEN = 28; /*  sizeof EtherARP != 28 */

} // namespace arp
} // namespace snort

#endif

/*
void dump_to_stdout(uint8_t *data, uint16_t size) {
    int r = 0;
    for (int i = 0 ; i < size; i++) {
      std::cout << std::format("{:02x} ", data[i]);
      if( ++r >= 16 ) {
        std::cout << "\n";
        r = 0;
      }
    }
    std::cout << std::endl;
}
*/

namespace {
const uint8_t null_hw_adr[6] = {0, 0, 0, 0, 0, 0};
const uint8_t broadcast_hw_adr[6]{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
} // namespace

void Inspector::eval(snort::Packet *p) {
  // std::cout << "MKRTEST: ARP Package:" << std::endl;

  Pegs::s_peg_counts.arp_packets++;

  const snort::arp::EtherARP *ah = snort::layer::get_arp_layer(p);

  switch (ntohs(ah->ea_hdr.ar_op)) {
  case ARPOP_REQUEST:
    // A request to one self, is the same as an anouncement
    // TODO: Check it is a broadcast on the ethernet level
    if (memcmp(ah->arp_tpa, ah->arp_spa, 4)) {
      Pegs::s_peg_counts.arp_requests++;
    } else {
      Pegs::s_peg_counts.arp_announcements++;
    }
    break;
  case ARPOP_REPLY:
    Pegs::s_peg_counts.arp_replies++;
    break;
  case ARPOP_RREQUEST:
    Pegs::s_peg_counts.arp_rrequests++;
    break;
  case ARPOP_RREPLY:
    Pegs::s_peg_counts.arp_rreplies++;
    break;
  default:
    Pegs::s_peg_counts.arp_unknown_command++;
  }

  //    PegCount arp_requests = 0;
  //    PegCount arp_replies = 0;
  //    PegCount arp_id_broadcasts = 0;

  if (!ah) {
    std::cout << "MKRTEST: NO ARP LAYER" << std::endl;
    return;
  }
  /*
    std::cout << "Command (" << ntohs(ah->ea_hdr.ar_op) << ") :";

    switch (ntohs(ah->ea_hdr.ar_op)) {
      case ARPOP_REQUEST:
        std::cout << "Requst";
        break;
      case ARPOP_REPLY:
        std::cout << "Reply";
        break;
      case ARPOP_RREQUEST:
        std::cout << "RRequst";
        break;
      case ARPOP_RREPLY:
        std::cout << "RReply";
        break;
      default:
        std::cout << "Invalid";
    }
  */
  // std::cout << std::endl;

  //  std::cout << "MKRTEST: pkt size = " << p->pktlen << std::endl;
  //  std::cout << "MKRTEST: payload size = " << p->dsize << std::endl;
  //  std::cout << "MKRTEST: apr size = " << sizeof(snort::arp::EtherARP) <<
  //  std::endl;
}

Inspector::Inspector(Module & /*module*/)
    //: settings(module.get_settings()), pegs(module.get_peg_counts()){
    {};

Inspector::~Inspector() {}

} // namespace arp_monitor
