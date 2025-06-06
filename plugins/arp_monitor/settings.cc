

// Snort includes

// System includes

// Global includes

// Local includes
#include "settings.h"

// Debug includes

namespace arp_monitor {

uint32_t Settings::get_timeout_ms() { return timeout_ms; }

LioLi::Logger &Settings::get_logger() {
  if (!logger) {
    logger = LioLi::LogDB::get<LioLi::Logger>(logger_name.c_str());
  }
  return *logger;
}

} // namespace arp_monitor
