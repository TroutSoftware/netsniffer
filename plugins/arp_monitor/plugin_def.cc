// Snort includes
#include <framework/decode_data.h>

// System includes

// Local includes
#include "inspector.h"
#include "module.h"
#include "plugin_def.h"

// Debug includes

namespace arp_monitor {

const snort::InspectApi inspect_api = {
    {PT_INSPECTOR, sizeof(snort::InspectApi), INSAPI_VERSION, 0, API_RESERVED,
     API_OPTIONS, Module::get_module_name(), Module::get_module_help(),
     Module::ctor, Module::dtor},
    snort::IT_PACKET,

    PROTO_BIT__ARP, // protocol filter
    nullptr,        // buffers
    nullptr,        // service
    nullptr,        // init
    nullptr,        // term
    nullptr,        // tinit
    nullptr,        // tterm
    Inspector::ctor,
    Inspector::dtor,
    nullptr, // ssn
    nullptr  // reset
};

} // namespace arp_monitor
