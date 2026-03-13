#ifndef settings_B8E4C71F
#define settings_B8E4C71F

// Snort includes

// System includes

// Global includes
#include <log_framework.h>

// Local includes

// Debug includes

namespace trout::discovery {

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

} // namespace trout_discovery

#endif // #ifndef settings_B8E4C71F
