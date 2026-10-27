#ifndef bacnet_ip_defs_37BEFE22
#define bacnet_ip_defs_37BEFE22

// Snort includes

// System includes
#include <cstddef>

// Global includes

// Local includes

// Debug includes


namespace bacnet_ip {

/// Fixed size of the bvlc struct
constexpr std::size_t BVLC_SIZE = 4;  

/// Fixed value for a BACnet/ip bvlc header type
constexpr uint8_t BVLS_BACNET_IP_TYPE = 0x81;

/// Minimum size for a NPDU struct
constexpr std::size_t NPDU_MIN_SIZE = 2;  

/// NPDU Control byte mask, it true Network_layer, otherwise APDU
constexpr uint8_t NPDU_IS_NETWORK_LAYER_MASK = 0x80;

/// NPDU Control byte mask, destination specifier is present
constexpr uint8_t NPDU_HAS_DEST_MASK = 0x20;

/// NPDU Control byte mask, source specifier is present
constexpr uint8_t NPDU_HAS_SRC_MASK = 0x08;

/// NPDU Control byte mask, msg expect a reply
constexpr uint8_t NPDU_REPLY_EXPECT_MASK = 0x04;

/// NPDU Control byte mask, priority
constexpr uint8_t NPDU_PRIORITY_MASK = 0x03;

/// NPDU Control priority, normal
constexpr uint8_t NPDU_PRIORITY_NORMAL = 0x00;

/// NPDU Control priority, urgent
constexpr uint8_t NPDU_PRIORITY_URGENT = 0x01;

/// NPDU Control priority, critical
constexpr uint8_t NPDU_PRIORITY_CRITICAL_EQUIP = 0x02;

/// NPDU Control priority, life safety
constexpr uint8_t NPDU_PRIORITY_LIFE_SAFETY = 0x03;

} // namespace bacnet_ip

#endif // #ifndef bacnet_ip_defs_37BEFE22
