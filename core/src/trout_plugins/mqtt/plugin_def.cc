
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes
#include <framework/decode_data.h> // Needed for PROTO_BIT__ALL

// System includes

// Local includes
#include "inspector.h"
#include "module.h"
#include "plugin_def.h"

// Debug includes

namespace mqtt_plugin {

// clang-format off
const snort::InspectApi inspect_api = {
    {
      PT_INSPECTOR,
      sizeof(snort::InspectApi),
      INSAPI_VERSION,
      0,
      API_RESERVED,
      API_OPTIONS,
      Module::get_module_name(),
      Module::get_module_help(),
      Module::ctor,
      Module::dtor
    },
    snort::IT_SERVICE,
    PROTO_BIT__PDU, // protocol filter (MQTT is TCP based, but in snort
                    // terms it is PDU, as it consumes PAF-generated
                    // PDU's through the splitter )
    nullptr,        // buffers
    "mqtt",         // service
    nullptr,        // init
    nullptr,        // term
    nullptr,        // tinit
    nullptr,        // tterm
    Inspector::ctor,
    Inspector::dtor,
    nullptr, // ssn
    nullptr  // reset
};
// clang-format on

} // namespace mqtt_plugin
