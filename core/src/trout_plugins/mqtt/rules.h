#ifndef rules_7A3F91C4
#define rules_7A3F91C4

// Snort includes
#include <detection/detection_engine.h>

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
  connack_message_malformed = 1112,
  com_on_refused_connection = 1113,
  server_out_of_sync = 1114,
  client_out_of_sync = 1115,
  topic_name_invalid = 1116,
  publish_message_malformed = 1117,
  puback_message_malformed = 1118,
  pubrec_message_malformed = 1119,
  pubrel_message_malformed = 1120,
  pubcomp_message_malformed = 1121,
  subscribe_message_malformed = 1122,
  suback_message_malformed = 1123,
  unsubscribe_message_malformed = 1124,
  unsuback_message_malformed = 1125,
  pingreq_message_malformed = 1126,
  pingresp_message_malformed = 1127,
  disconnect_message_malformed = 1128,
  unsupported_version = 1129,
  reserved_message = 1130,
  connect_message_misplaced = 1131,
};

constexpr unsigned gid = Common::trout_gid; // Module wide GID

inline unsigned U(SID sid) { return static_cast<unsigned>(sid); }

inline void queue(SID sid) { snort::DetectionEngine::queue_event(gid, U(sid)); }

extern const snort::RuleMap s_rules[];

} // namespace mqtt_plugin

#endif // #ifndef rules_7A3F91C4
