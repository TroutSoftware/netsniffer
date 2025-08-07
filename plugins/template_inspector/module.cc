

// Snort includes

// System includes

// Global includes

// Local includes
#include "module.h"
#include "pegs.h"

// Debug includes

// Anonomous namespace, i.e. internal linking (won't interfere with things
// outside of this file)
namespace {

const char *s_name =
    "my_plugin_name"; // TODO: Replace with the name of the plugin
const char *s_help =
    "Help text for plugin"; // TODO: Replace with help text for your plugin

// TODO: Sample parameteres, replace with your own
const snort::Parameter module_params[] = {
    {"logger", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Set logger output should be sent to"},
    {"testmode", snort::Parameter::PT_BOOL, nullptr, "false",
     "Testmode will make deterministic (fake) timestamps"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

} // namespace

namespace my_plugin_name {

bool Module::begin(const char *, int, snort::SnortConfig *) {
  settings = std::make_shared<Settings>();
  return true;
}

bool Module::end(const char *, int, snort::SnortConfig *) { return true; }

bool Module::set(const char *, snort::Value &val, snort::SnortConfig *) {
  // TODO: Update this so it matches the actual parameters in module_params[]
  if (val.is("logger") && val.get_as_string().size() > 0) {
    settings->logger_name = val.get_as_string();
  } else if (val.is("testmode")) {
    settings->testmode = val.get_bool();
  } else {
    // fail if we didn't get something we knew about
    return false;
  }

  return true;
}

const PegInfo *Module::get_pegs() const { return Pegs::s_pegs; }

PegCount *Module::get_counts() const {
  return reinterpret_cast<PegCount *>(&Pegs::s_peg_counts);
}

Module::Module()
    : snort::Module(get_module_name(), get_module_help(), module_params) {}

Module::~Module() {}

Module::Usage Module::get_usage() const { return INSPECT; }

const char *Module::get_module_name() { return s_name; }

const char *Module::get_module_help() { return s_help; }

std::shared_ptr<Settings> Module::get_settings() { return settings; }

} // namespace my_plugin_name
