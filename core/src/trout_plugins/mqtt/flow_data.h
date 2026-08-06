#ifndef flow_data_7A3F91C4
#define flow_data_7A3F91C4

// Snort includes

// System includes
#include <variant>

// Global includes
#include "../includes/flow_data.h"

// Local includes
#include "mqtt_protocol_defs.h"

// Debug includes

namespace mqtt_plugin {

struct FlowData {
  bool in_sync = true;
  uint8_t protocol_level = 0;    // MQTT version: 3 = 3.1, 4 = 3.1.1, 5 = 5.0
  MsgType msg_type = MsgType::Reserved;
  uint32_t remaining_from_header = 0;   // Used during parsing
  uint32_t variable_header_start = 0;   // Used during parsing
  std::vector<uint8_t> client_id;       // Populated from the connect message
  std::variant<std::monostate,          // Must be first entry, as it will then be the default
               ConnectMsg> cur_msg;

};

using PacketFlowData = Common::FlowData<FlowData>;

} // namespace trout_netflow2

#endif // #ifndef flow_data_7A3F91C4
