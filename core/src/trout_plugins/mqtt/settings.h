#ifndef settings_B57239EF
#define settings_B57239EF

// Snort includes

// System includes

// Global includes
#include "../wrappers/parameter_param.h"
#include "../wrappers/parameter_param_list.h"

// Local includes
#include "client_id_monitor.h"

// Debug includes

namespace mqtt_plugin {

using namespace trout::templates;

class ClientIDMonitorType : public GenericTypeBaseClass {
   std::unique_ptr<ClientIDMonitor> client_id_monitor;

public:
  static consteval snort::Parameter::Type get_type() {
    return snort::Parameter::PT_INT;
  }

  void set(snort::Value &val) {
    // TODO: Delay this to the end, and implement generic validation
    client_id_monitor = std::make_unique<ClientIDMonitor>(val.get_uint32());
  }

  ClientIDMonitor &get() {
    assert(client_id_monitor); // The DefaultValue<> should prevent this

    return *client_id_monitor;
  }
};

static_assert(TypeConcept<ClientIDMonitorType>,
              "ClientIDMonitorType is not compliant with ConceptType");


// clang-format off
using Settings = ParamList< Param<  Name<"client_id_cache_min_size">,
                                    ClientIDMonitorType,
                                    SimpleRange<"1:10000">,
                                    DefaultValue<"1000">,
                                    HelpText<"Minimum size for list of Client ID's used to detect new client ID's / Client id's with a changed IP">>>;
// clang-format on


} // namespace mqtt_plugin

#endif // #ifndef settings_B57239EF
