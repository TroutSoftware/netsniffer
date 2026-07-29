#ifndef flow_data_7A3F91C4
#define flow_data_7A3F91C4

// Snort includes

// System includes

// Global includes
#include "../includes/flow_data.h"

// Local includes


// Debug includes

namespace mqtt_plugin {

struct FlowData {
  uint8_t protocol_level=0;    // MQTT version: 3 = 3.1, 4 = 3.1.1, 5 = 5.0

};

using PacketFlowData = Common::FlowData<FlowData>;

} // namespace trout_netflow2

#endif // #ifndef flow_data_7A3F91C4
