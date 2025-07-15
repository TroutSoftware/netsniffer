#ifndef gid_sid_cc759bfe
#define gid_sid_cc759bfe

// Snort includes
#include <framework/module.h>

// System includes

// Global includes
#include <trout_gid.h>

// Local includes

// Debug includes

namespace icmp_logger {

constexpr unsigned icmp_logger_gid = Common::trout_gid;
constexpr unsigned icmp_logger_destination_unreachable = 1070;

constexpr snort::RuleMap s_rules[] = {
    {icmp_logger_destination_unreachable, "destination unreachable"},
    {0, nullptr}};

} // namespace icmp_logger

#endif // #ifndef gid_sid_cc759bfe
