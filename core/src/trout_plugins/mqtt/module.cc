
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes

// System includes

// Global includes

// Local includes
#include "module.h"
// #include "pegs.h"
#include "rules.h"

// Debug includes

namespace mqtt_plugin {

unsigned Module::get_gid() const { return gid; }
const snort::RuleMap *Module::get_rules() const { return s_rules; }

Module::Module() {}

Module::~Module() {}

} // namespace mqtt_plugin
