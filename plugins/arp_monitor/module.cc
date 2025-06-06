

// Snort includes

// System includes

// Global includes

// Local includes
#include "module.h"
#include "pegs.h"

// Debug includes

namespace {

const char *s_name = "arp_monitor";
const char *s_help = "dumps arp info to logger";

const snort::Parameter module_params[] = {
    {"alert_time_out_ms", snort::Parameter::PT_INT, "0:max31", "1000",
     "An alert might be generated if an arp response hasn't been seen before "
     "the value in ms"},
    {"logger", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Set logger output should be sent to"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

} // namespace

namespace arp_monitor {

bool Module::begin(const char *, int, snort::SnortConfig *) { return true; }

bool Module::end(const char *, int, snort::SnortConfig *) { return true; }

bool Module::set(const char *, snort::Value &val, snort::SnortConfig *) {
  if (val.is("logger") && val.get_as_string().size() > 0) {
    settings->logger_name = val.get_string();
  } else if (val.is("alert_time_out_ms")) {
    settings->timeout_ms = val.get_uint32();
  } else {
    // fail if we didn't get something valid
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

} // namespace arp_monitor
