
#ifndef pegs_E04A7D29
#define pegs_E04A7D29

// Snort includes
#include <framework/counts.h>

// System includes

// Global includes

// Local includes

// Debug includes

namespace mqtt_plugin {

struct Pegs {

  // TODO: Replace with the pegs that your module uses
  struct PegCounts {
    PegCount flows_detected = 0;
  };

  static PegInfo s_pegs[];
  static PegCounts s_peg_counts;
};

// This must match the s_pegs[] array

} // namespace mqtt_plugin

#endif // #ifndef pegs_E04A7D29
