#ifndef module_213322FE
#define module_213322FE

// Snort includes

// System includes

// Global includes
#include <trout_plugins/wrappers/module.h>

// Local includes
#include "pegs.h"
#include "settings.h"

// Debug includes

namespace bacnet_ip {

// clang-format off
using namespace trout::templates;
class Module : public trout::templates::Module<
                   Pegs,
                   Settings,
                   Name<"bacnet_ip">,
                   HelpText<"bacnet_ip is currently a pure address inspector">> {
  // clang-format on

  Module();
  ~Module();

  Usage get_usage() const override { return INSPECT; }

  bool is_bindable() const override { return true; }

public:
  static snort::Module *ctor() { return new Module(); }
  static void dtor(snort::Module *p) { delete p; }
};

} // namespace bacnet_ip

#endif // #ifndef module_213322FE
