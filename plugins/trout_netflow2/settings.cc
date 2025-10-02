
// Snort includes

// System includes

// Global includes

// Local includes
#include "settings.h"

// Debug includes

namespace trout_netflow2 {

LioLi::Logger &Settings::get_logger() {
  if (!logger) {
    logger = LioLi::LogDB::get<LioLi::Logger>(logger_name.c_str());
  }
  return *logger;
}

bool Settings::get_testmode() { return testmode; }

bool Settings::get_generate_service_map() { return generate_service_map; }

uint32_t Settings::get_max_cache_size() { return cache_size; }

uint32_t Settings::get_flush_interval_ms() { return flush_interval_ms; }

} // namespace trout_netflow2
