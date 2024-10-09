#ifndef trout_netflow_8f0b2765
#define trout_netflow_8f0b2765

// Snort includes
#include <framework/base_api.h>
#include <framework/counts.h>
#include <framework/inspector.h>

// System includes

// Local includes

namespace trout_netflow {

extern const snort::InspectApi inspect_api;

// TODO(MKR): Move this to separate header file so it doesn't get public

const PegInfo s_pegs[] = {
    {CountType::SUM, "packets processed", "Number of packages processed"},
    {CountType::SUM, "services detected", "Number of services detected"},
    {CountType::SUM, "packets total size", "Sum of size of all packages"},
    {CountType::SUM, "payload total size", "Sum of size of all payloads"},
    {CountType::END, nullptr, nullptr}};

// This must match the s_pegs[] array
struct PegCounts {
  PegCount pkg_processed = 0;
  PegCount srv_detected = 0;
  PegCount pkt_size = 0;
  PegCount payload_size = 0;
};

// This must match the s_pegs[] array
extern THREAD_LOCAL struct PegCounts s_peg_counts;

} // namespace trout_netflow

#endif // #ifndef netflow_to_lioli_8f0b2765
