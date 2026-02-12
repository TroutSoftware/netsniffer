
// Snort includes

// System includes

// Global includes

// Local includes
#include "settings.h"

// Debug includes

namespace trout_netflow2 {

LioLi::Logger &Settings::get_logger() {
  if (!logger || !(*logger)) {
    logger = LioLi::LogDB::get<LioLi::Logger>(logger_name.c_str());
  }
  return *logger;
}

bool Settings::get_testmode() { return testmode; }

bool Settings::get_generate_service_map() { return generate_service_map; }

bool Settings::get_do_ping() { return do_ping; }

bool Settings::get_extended_console_logging() {
  return extended_console_logging;
}

uint8_t Settings::get_undefined_ip_protocol_number() {
  return undefined_ip_protocol_number;
}

uint32_t Settings::get_max_cache_size() { return cache_size; }

uint32_t Settings::get_flush_interval_ms() { return flush_interval_ms; }

uint32_t Settings::get_source_id() { return source_id; }

std::string Settings::get_logger_name() { return logger_name; }

} // namespace trout_netflow2
