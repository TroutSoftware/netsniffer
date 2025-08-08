
#ifndef pegs_fd184bba
#define pegs_fd184bba

// Snort includes
#include <framework/counts.h>

// System includes

// Global includes

// Local includes

// Debug includes

namespace trout_netflow2 {

struct Pegs {

  struct PegCounts {
    PegCount flows_seen = 0;        // Updated by inspector
    PegCount pkts_without_flow = 0; // Updated by inspector
    PegCount pkts_seen = 0;         // Updated by inspector
    PegCount total_bytes = 0;       // Updated by cache
  };

  static PegInfo s_pegs[];
  static PegCounts s_peg_counts;
};

// This must match the s_pegs[] array

} // namespace trout_netflow2

#endif // #ifndef pegs_fd184bba
