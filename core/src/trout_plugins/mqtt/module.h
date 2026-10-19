#ifndef module_3B91DE57
#define module_3B91DE57

// Snort includes
#include <framework/module.h>

// System includes

// Global includes
#include <trout_plugins/wrappers/module.h>

// Local includes
#include "pegs.h"
#include "settings.h"

// Debug includes

namespace mqtt_plugin {

// clang-format off
using namespace trout::templates;
class Module : public trout::templates::Module<
                   Pegs,
                   Settings,
                   Name<"mqtt">,
                   HelpText<"mqtt inspector">> {
  // clang-format on

  Module();
  ~Module();

  Usage get_usage() const override { return INSPECT; }

  bool is_bindable() const override { return true; }

  unsigned get_gid() const override;
  const snort::RuleMap *get_rules() const override;

public:
  static snort::Module *ctor() { return new Module(); }
  static void dtor(snort::Module *p) { delete p; }
};

} // namespace mqtt_plugin

#endif // #ifndef module_3B91DE57
