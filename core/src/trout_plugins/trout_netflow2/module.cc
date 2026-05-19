
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes

// System includes

// Global includes

// Local includes
#include "module.h"
#include "pegs.h"

// Debug includes

namespace {

const char *s_name = "trout_netflow2";
const char *s_help = "generates netflow data";

const snort::Parameter module_params[] = {
    {"logger", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Set logger output should be sent to"},
    {"testmode", snort::Parameter::PT_BOOL, nullptr, "false",
     "Testmode will aim for deterministic output, including (fake) "
     "timestamps "},
    {"cache_size", snort::Parameter::PT_INT, "1:100000", "10000",
     "The max number of simultaneous conections that can be handled at any "
     "given time"},
    {"flush_interval_ms", snort::Parameter::PT_INT, "10:100000", "100",
     "Max target interval in ms for flushing the cache to the logger after "
     "last flush, might flush sooner if cache is getting full, and might be "
     "delayed on a loaded system"},
    {"template_resend_interval_s", snort::Parameter::PT_INT, "0:86400", "5",
     "How often templates are resend in s.  The templates will be generated "
     "with the following cache flush.  Templates won't be generated at regular "
     "intervals if value is set to 0"},
    {"generate_service_map", snort::Parameter::PT_BOOL, nullptr, "false",
     "Will add service map generation to the output"},
    {"source_id", snort::Parameter::PT_INT, "0:4294967295", "0",
     "Set the Source ID transmitted in the Packet Header"},
    {"do_ping", snort::Parameter::PT_BOOL, nullptr, "false",
     "Will generate empty packages at least every flush_interval"},
    {"extended_console_logging", snort::Parameter::PT_BOOL, nullptr, "false",
     "Will enable more logs to the console of what is happening in the module"},
    {"undefined_ip_protocol_number", snort::Parameter::PT_INT, "0:255", "0",
     "Set the value exported in the PROTOCOL (4) field, when the flow is not "
     "ip packet based"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

} // namespace

namespace trout_netflow2 {

bool Module::begin(const char *, int, snort::SnortConfig *) {
  settings = std::make_shared<Settings>();
  return true;
}

bool Module::end(const char *, int, snort::SnortConfig *) { return true; }

bool Module::set(const char *, snort::Value &val, snort::SnortConfig *) {
  if (val.is("logger") && val.get_as_string().size() > 0) {
    settings->logger_name = val.get_as_string();
  } else if (val.is("testmode")) {
    settings->testmode = val.get_bool();
  } else if (val.is("generate_service_map")) {
    settings->generate_service_map = val.get_bool();
  } else if (val.is("cache_size")) {
    settings->cache_size = val.get_uint32();
  } else if (val.is("flush_interval_ms")) {
    settings->flush_interval_ms = val.get_uint32();
  } else if (val.is("template_resend_interval_s")) {
    settings->template_resend_interval_s = val.get_uint32();
  } else if (val.is("source_id")) {
    settings->source_id = val.get_uint32();
  } else if (val.is("do_ping")) {
    settings->do_ping = val.get_bool();
  } else if (val.is("extended_console_logging")) {
    settings->extended_console_logging = val.get_bool();
  } else if (val.is("undefined_ip_protocol_number")) {
    settings->undefined_ip_protocol_number = val.get_uint8();
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

} // namespace trout_netflow2
