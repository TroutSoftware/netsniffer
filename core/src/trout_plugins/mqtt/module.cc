
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes

// System includes

// Global includes

// Local includes
#include "module.h"
#include "pegs.h"
#include "rules.h"

// Debug includes

// Anonomous namespace, i.e. internal linking (won't interfere with things
// outside of this file)
namespace {

const char *s_name =
    "mqtt"; // TODO: Replace with the name of the plugin
const char *s_help =
    "mqtt inspector"; // TODO: Replace with help text for your plugin


} // namespace

namespace mqtt_plugin {

bool Module::begin(const char *, int, snort::SnortConfig *) {
  settings = std::make_shared<Settings>();
  return true;
}

bool Module::end(const char *, int, snort::SnortConfig *) { return true; }

bool Module::set(const char *, snort::Value &val, snort::SnortConfig *) {
  return settings->set(val.get_name(), val);
}

const PegInfo *Module::get_pegs() const { return Pegs::s_pegs; }

PegCount *Module::get_counts() const {
  return reinterpret_cast<PegCount *>(&Pegs::s_peg_counts);
}

unsigned Module::get_gid() const { return gid; }
const snort::RuleMap *Module::get_rules() const { return s_rules; }


Module::Module()
    : snort::Module(get_module_name(), get_module_help(), Settings::generate_snort_def()) {}

Module::~Module() {}

Module::Usage Module::get_usage() const { return INSPECT; }

const char *Module::get_module_name() { return s_name; }

const char *Module::get_module_help() { return s_help; }

std::shared_ptr<Settings> Module::get_settings() { return settings; }

} // namespace mqtt_plugin
