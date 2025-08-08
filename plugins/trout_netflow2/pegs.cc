// Snort includes

// System includes

// Global includes

// Local includes
#include "pegs.h"

// Debug includes

namespace trout_netflow2 {

PegInfo Pegs::s_pegs[] = {
    {CountType::SUM, "flows_seen", "Number of snort flows seen"},
    {CountType::SUM, "pkts_without_flow",
     "Number of packets seen without a flow"},
    {CountType::SUM, "pkts_seen", "Number of packets seen"},
    {CountType::SUM, "total_bytes", "Sum of size of all packets seen"},

    {CountType::END, nullptr, nullptr}};

Pegs::PegCounts Pegs::s_peg_counts;

// Compile time sanity check of number of entries in s_pegs and s_peg_counts
static_assert(
    (sizeof(Pegs::s_pegs) / sizeof(PegInfo)) - 1 ==
        sizeof(Pegs::PegCounts) / sizeof(PegCount),
    "Entries in s_pegs doesn't match number of entries in s_peg_counts");

} // namespace trout_netflow2
