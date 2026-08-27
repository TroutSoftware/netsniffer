
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes

// System includes

// Global includes

// Local includes
#include "rules.h"

// Debug includes

// SID List

namespace mqtt_plugin {

const snort::RuleMap s_rules[] = {
    {U(SID::connect_message_malformed), "CONNECT message malformed"},
    {U(SID::message_has_extra_data), "Message has hidden data"},
    {U(SID::connack_message_malformed), "CONNACK message malformed"},
    {U(SID::com_on_refused_connection), "Communication on refused flow"},
    {U(SID::server_out_of_sync), "Gave up parsing server data, stream has gone out of sync"},
    {U(SID::client_out_of_sync), "Gave up parsing client data, stream has gone out of sync"},
    {U(SID::topic_name_invalid), "Found illegal topic name"},
    {U(SID::publish_message_malformed), "PUBLISH message malformed"},
    {U(SID::puback_message_malformed), "PUBACK message malformed"},
    {U(SID::pubrec_message_malformed), "PUBREC message malformed"},
    {U(SID::pubrel_message_malformed), "PUBREL message malformed"},
    {U(SID::pubcomp_message_malformed), "PUBCOMP message malformed"},
    {U(SID::subscribe_message_malformed), "SUBSCRIBE message malformed"},
    {U(SID::suback_message_malformed), "SUBACK message malformed"},
    {U(SID::unsubscribe_message_malformed), "UNSUBSCRIBE message malformed"},
    {U(SID::unsuback_message_malformed), "UNSUBSCRIBE message malformed"},
    {U(SID::pingreq_message_malformed), "PINGREQ message malformed"},
    {U(SID::pingresp_message_malformed), "PINGRESP message malformed"},
    {U(SID::disconnect_message_malformed), "DISCONNECT message malformed"},
    {U(SID::unsupported_version), "Flow is in a protocol version we don't support"},
    {U(SID::reserved_message), "Reserved message (for the given version) found in stream"},
    {U(SID::connect_message_misplaced), "Connect message was seen, but not as the first message"},
    {U(SID::new_ip_for_client_id), "A client ID was either seen for the first time, or seen on a new IP"},
    {0, nullptr}
};

} // namespace mqtt_plugin {
