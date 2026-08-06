#ifndef rules_7A3F91C4
#define rules_7A3F91C4

// Snort includes

// System includes

// Global includes
#include "../includes/trout_gid.h"
#include "framework/module.h"

// Local includes

// Debug includes

namespace mqtt_plugin {

enum class SID {
  connect_message_malformed = 1110,
  message_has_extra_data = 1111,
};

constexpr unsigned gid = Common::trout_gid; // Module wide GID

inline unsigned U(SID sid) { return static_cast<unsigned>(sid); }

extern const snort::RuleMap s_rules[];

} // namespace mqtt_plugin

#endif // #ifndef rules_7A3F91C4
