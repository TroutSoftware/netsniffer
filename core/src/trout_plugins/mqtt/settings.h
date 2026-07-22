#ifndef settings_B57239EF
#define settings_B57239EF

// Snort includes

// System includes

// Global includes
#include "../includes/log_framework.h"

// Local includes

// Debug includes

namespace mqtt_plugin {

class Module;

class Settings {
  friend Module;

  std::string logger_name;
  std::shared_ptr<LioLi::Logger> logger;
  bool testmode;

public:
  LioLi::Logger &get_logger();
  bool get_testmode();
};

} // namespace mqtt_plugin

#endif // #ifndef settings_B57239EF
