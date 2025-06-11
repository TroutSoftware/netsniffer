// Snort includes

// System includes

// Global includes

// Local includes
#include "pegs.h"

// Debug includes

namespace arp_monitor {

PegInfo Pegs::s_pegs[] = {
    {CountType::SUM, "arp packets", "Number of arp packages processed"},
    {CountType::SUM, "arp requests", "Number of arp requests seen"},
    {CountType::SUM, "arp misformed requests",
     "Number of arp requests we couldn't decode"},
    {CountType::SUM, "arp replies", "Number of arp replies seen"},
    {CountType::SUM, "arp rrequests", "Number of arp reverse requests"},
    {CountType::SUM, "arp rreplies", "Number of arp reverse replies"},
    {CountType::SUM, "arp announcements", "Number of arp announcements"},
    {CountType::SUM, "arp unknown command", "Number of unknown arp commands"},
    {CountType::SUM, "arp request overflow",
     "Number of request overflows, try to increase max_req_queue if seen"},
    {CountType::END, nullptr, nullptr}};

Pegs::PegCounts Pegs::s_peg_counts;

// Compile time sanity check of number of entries in s_pegs and s_peg_counts
static_assert(
    (sizeof(Pegs::s_pegs) / sizeof(PegInfo)) - 1 ==
        sizeof(Pegs::PegCounts) / sizeof(PegCount),
    "Entries in s_pegs doesn't match number of entries in s_peg_counts");

} // namespace arp_monitor
