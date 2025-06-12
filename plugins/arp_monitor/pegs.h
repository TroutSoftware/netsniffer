
#ifndef pegs_01121348
#define pegs_01121348

// Snort includes
#include <framework/counts.h>

// System includes
#include <cstdint>
#include <memory>

// Global includes
#include <log_framework.h>

// Local includes

// Debug includes

namespace arp_monitor {

struct Pegs {

  struct PegCounts {
    PegCount arp_packets = 0;
    PegCount arp_requests = 0;
    PegCount arp_misformed_requests = 0;
    PegCount arp_replies = 0;
    PegCount arp_rrequests = 0;
    PegCount arp_rreplies = 0;
    PegCount arp_announcements = 0;
    PegCount arp_unknown_command = 0;
    PegCount arp_request_overflow = 0;
    PegCount arp_orphan_reply = 0;
    PegCount arp_matches = 0;
    PegCount arp_late_match = 0;
    PegCount arp_unmatched = 0;
  };

  static PegInfo s_pegs[];
  static PegCounts s_peg_counts;
};

// This must match the s_pegs[] array

} // namespace arp_monitor

#endif // #ifndef pegs_01121348
