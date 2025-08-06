
// Snort includes

// System includes

// Global includes

// Local includes
#include "settings.h"

// Debug includes

namespace my_plugin_name {

LioLi::Logger &Settings::get_logger() {
  if (!logger) {
    logger = LioLi::LogDB::get<LioLi::Logger>(logger_name.c_str());
  }
  return *logger;
}

bool Settings::get_testmode() { return testmode; }

} // namespace my_plugin_name
