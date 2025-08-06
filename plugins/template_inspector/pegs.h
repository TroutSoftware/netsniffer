
#ifndef pegs_[RANDOM_32BIT_HEX_NUMBER]
#define pegs_ [RANDOM_32BIT_HEX_NUMBER]

// Snort includes
#include <framework/counts.h>

// System includes

// Global includes

// Local includes

// Debug includes

namespace my_plugin_name {

struct Pegs {

  // TODO: Replace with the pegs that your module uses
  struct PegCounts {
    PegCount flows_detected = 0;
  };

  static PegInfo s_pegs[];
  static PegCounts s_peg_counts;
};

// This must match the s_pegs[] array

} // namespace my_plugin_name

#endif // #ifndef pegs_[RANDOM_32BIT_HEX_NUMBER]
