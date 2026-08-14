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
  // Debug
  int get_flow_id() {
    static int id = 0;
    return ++id;
  }
  int flow_id = get_flow_id();

  bool server_in_sync = true;
  bool client_in_sync = true;
  uint8_t protocol_level = 0;    // MQTT version: 3 = 3.1, 4 = 3.1.1, 5 = 5.0
  MsgType msg_type = MsgType::Reserved;
  //uint32_t remaining_from_header = 0;   // Used during parsing
  uint32_t variable_header_start = 0;   // Used during parsing
  std::optional<std::span<const uint8_t>> extra;  // extra data that couldn't be parsed
  std::vector<uint8_t> client_id;       // Populated from the connect message
  std::variant<std::monostate,          // monostate must be first entry, as it will then be the default
               ConnectMsg,
               ConnAckMsg,
               PublishMsg,
               PubAckMsg,
               PubRecMsg,
               PubRelMsg,
               PubCompMsg,
               SubscribeMsg
               > cur_msg;
  bool connection_refused = false;      // Connection has been refused by either party

};

using PacketFlowData = Common::FlowData<FlowData>;

} // namespace trout_netflow2

#endif // #ifndef flow_data_7A3F91C4
