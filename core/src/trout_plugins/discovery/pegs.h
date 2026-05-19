
#ifndef pegs_A7D4E2C9
#define pegs_A7D4E2C9

// Snort includes
#include <framework/counts.h>

// System includes

// Global includes

// Local includes

// Debug includes

namespace trout::discovery {

struct Pegs {

  // TODO: Replace with the pegs that your module uses
  struct PegCounts {
    PegCount flows_detected = 0;
  };

  static PegInfo s_pegs[];
  static PegCounts s_peg_counts;
};

// This must match the s_pegs[] array

} // namespace trout::discovery

#endif // #ifndef pegs_A7D4E2C9
