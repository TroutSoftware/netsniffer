
// TODO: This file is heavily WIP....

// Snort includes

// System includes

// Global includes

// TMP template includes, move to global
#include "parameter_param.h"
#include "parameter_param_list.h"

// Local includes
#include "module.h"
#include "pegs.h"

// Debug includes

// Anonomous namespace, i.e. internal linking (won't interfere with things
// outside of this file)
namespace {

const char *s_name = "discovery"; 
const char *s_help =
    "Help text for plugin"; // TODO: Replace with help text for your plugin

} // namespace

namespace trout::discovery {

bool Module::begin(const char *, int, snort::SnortConfig *) { return true; }

bool Module::end(const char *, int, snort::SnortConfig *) { return true; }

bool Module::set(const char *, snort::Value &val, snort::SnortConfig *) {
  return settings->set(val.get_name(), val);
}

const PegInfo *Module::get_pegs() const { return Pegs::s_pegs; }

PegCount *Module::get_counts() const {
  return reinterpret_cast<PegCount *>(&Pegs::s_peg_counts);
}

Module::Module()
    : snort::Module(get_module_name(), get_module_help(),
                    Settings::generate_snort_def()) {}

Module::~Module() {}

Module::Usage Module::get_usage() const { return INSPECT; }

const char *Module::get_module_name() { return s_name; }

const char *Module::get_module_help() { return s_help; }

std::shared_ptr<Settings> Module::get_settings() { return settings; }

} // namespace trout::discovery
