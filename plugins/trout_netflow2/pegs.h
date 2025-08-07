
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
    PegCount flows_detected = 0;
  };

  static PegInfo s_pegs[];
  static PegCounts s_peg_counts;
};

// This must match the s_pegs[] array

} // namespace trout_netflow2

#endif // #ifndef pegs_fd184bba
