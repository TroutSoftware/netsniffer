
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
    {U(SID::connect_message_malformed), "Connect message malformed"},
    {U(SID::message_has_extra_data), "Message has hidden data"},
    {U(SID::connack_message_malformed), "Connack message malformed"},
    {U(SID::com_on_refused_connection), "Communication on refused flow"},
    {U(SID::server_out_of_sync), "Gave up parsing server data, stream has gone out of sync"},
    {U(SID::client_out_of_sync), "Gave up parsing client data, stream has gone out of sync"},
    {U(SID::topic_name_invalid), "Found illegal topic name"},
    {U(SID::publish_message_malformed), "Publish message malformed"},
    {U(SID::puback_message_malformed), "Puback message malformed"},
};

} // namespace mqtt_plugin {
