
#ifndef pegs_3b9f5af2
#define pegs_3b9f5af2

// Snort includes
#include <framework/counts.h>

// System includes
#include <cstdint>
#include <memory>

// Global includes
#include <log_framework.h>

// Local includes

// Debug includes

namespace icmp_logger {

struct Pegs {

  struct PegCounts {
    PegCount icmp_packets = 0;
  };

  static PegInfo s_pegs[];
  static PegCounts s_peg_counts;
};

// This must match the s_pegs[] array

} // namespace icmp_logger

#endif // #ifndef pegs_3b9f5af2
