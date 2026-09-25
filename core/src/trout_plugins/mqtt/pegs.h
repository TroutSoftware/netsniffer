
#ifndef pegs_E04A7D29
#define pegs_E04A7D29

// Snort includes
#include <framework/counts.h>

// System includes

// Global includes
#include "../wrappers/pegs_peg_list.h"

// Local includes

// Debug includes

namespace mqtt_plugin {

using namespace trout::templates;

// clang-format off
using Pegs = PegList<
  Peg<Name<"client_id_cache_max_size">, Type<PegType::MAX>, HelpText<"The max number of entries found in the client id cache">>,
  Peg<Name<"client_id_cache_purged">,   Type<PegType::SUM>, HelpText<"Cache entries that were purged">>,
  Peg<Name<"client_id_reassigned_ip">,  Type<PegType::SUM>, HelpText<"Times a known client id got a new ip address">>,
  Peg<Name<"com_when_refused">,         Type<PegType::SUM>, HelpText<"Packets seen on flow that should have been closed">>,
  Peg<Name<"flow_count">,               Type<PegType::SUM>, HelpText<"Number of MQTT flows">>,
  Peg<Name<"msg_with_extra_data">,      Type<PegType::SUM>, HelpText<"Messages with extra data (msg contains 'hidden' data)">>,
  Peg<Name<"multimsg_packages">,        Type<PegType::SUM>, HelpText<"Times a package received had multiple MQTT messages embedded">>,
  Peg<Name<"new_ip_client_id">,         Type<PegType::SUM>, HelpText<"Times a new ip/client id pair was seen">>,
  Peg<Name<"messages">,                 Type<PegType::SUM>, HelpText<"Packages presented to MQTT inspector (MQTT Messages)">>,
  Peg<Name<"packages_wo_flow">,         Type<PegType::SUM>, HelpText<"Packages received by splitter without a flow">>,
  Peg<Name<"protocol_3_1">,             Type<PegType::SUM>, HelpText<"MQTT 3.1 protocol connections seen">>,
  Peg<Name<"protocol_3_1_1">,           Type<PegType::SUM>, HelpText<"MQTT 3.1.1 protocol connections seen">>,
  Peg<Name<"protocol_5_0">,             Type<PegType::SUM>, HelpText<"MQTT 5.0 protocol connections seen">>,
  Peg<Name<"protocol_unsuported">,      Type<PegType::SUM>, HelpText<"Unsupported protocols seen (i.e. sum of 3.1.1 and 5.0) (counted once per flow)">>,
  Peg<Name<"protocol_unsuported_msg">,  Type<PegType::SUM>, HelpText<"Messages with unsupported protocols seen (counted once per msg)">>,
  Peg<Name<"rejected_flow_count">,      Type<PegType::SUM>, HelpText<"Flows that couldn't be passed as mqtt">>,
  Peg<Name<"scan_count">,               Type<PegType::SUM>, HelpText<"Times the splitter was called with data">>,
  Peg<Name<"split_packages">,           Type<PegType::SUM>, HelpText<"MQTT messages that was split across several network packages">>
>;
// clang-format on

} // namespace mqtt_plugin

#endif // #ifndef pegs_E04A7D29
