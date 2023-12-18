#include "protocols/packet.h"

namespace xsnort {
const uint8_t *packet_databuf(const snort::Packet &pkt) { return pkt.data; }
uint16_t packet_datalen(const snort::Packet &pkt) { return pkt.dsize; }
} // namespace xsnort