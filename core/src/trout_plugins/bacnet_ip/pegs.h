
#ifndef pegs_AD2B7AF5
#define pegs_AD2B7AF5

// Snort includes

// System includes

// Global includes
#include <trout_plugins/wrappers/pegs_peg_list.h>

// Local includes

// Debug includes


namespace bacnet_ip {

using namespace trout::templates;

// clang-format off
using Pegs = PegList<
  Peg<Name<"packages_received">,            Type<PegType::SUM>, HelpText<"The number of network packages that passed through the bacnet_ip module">>,
  Peg<Name<"udp_packages_received">,        Type<PegType::SUM>, HelpText<"The number of UDP packages receved">>,
  Peg<Name<"packet_underflow">,             Type<PegType::SUM>, HelpText<"Not enough data in packet to decode">>,
  Peg<Name<"packet_extra_data">,            Type<PegType::SUM>, HelpText<"Packets that contains data that isn't part of the message">>,
  Peg<Name<"packet_extra_data_sum">,        Type<PegType::SUM>, HelpText<"Sum of all extra data in packets">>,
  Peg<Name<"bacnet_ip_packets_received">,   Type<PegType::SUM>, HelpText<"BACnet/ip packets recevied">>
>;
// clang-format on


} // namespace bacnet_ip

#endif // #ifndef pegs_AD2B7AF5
