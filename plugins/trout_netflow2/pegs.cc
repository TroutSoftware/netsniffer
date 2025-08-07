// Snort includes

// System includes

// Global includes

// Local includes
#include "pegs.h"

// Debug includes

namespace trout_netflow2 {

PegInfo Pegs::s_pegs[] = {
    {CountType::SUM, "flows_detected", "Number of flows detected by snort"},
    {CountType::END, nullptr, nullptr}};

Pegs::PegCounts Pegs::s_peg_counts;

// Compile time sanity check of number of entries in s_pegs and s_peg_counts
static_assert(
    (sizeof(Pegs::s_pegs) / sizeof(PegInfo)) - 1 ==
        sizeof(Pegs::PegCounts) / sizeof(PegCount),
    "Entries in s_pegs doesn't match number of entries in s_peg_counts");

} // namespace trout_netflow2
