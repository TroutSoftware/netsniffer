#ifndef settings_[RANDOM_32BIT_HEX_NUMBER]
#define settings_ [RANDOM_32BIT_HEX_NUMBER]

// Snort includes

// System includes

// Global includes
#include <log_framework.h>

// Local includes

// Debug includes

namespace my_plugin_name {

class module;

struct Settings {
  friend module;

  std::string logger_name;
  std::shared_ptr<LioLi::Logger> logger;
  bool testmode;

public:
  LioLi::Logger &get_logger();
  bool get_testmode();
};

} // namespace my_plugin_name

#endif // #ifndef settings_[RANDOM_32BIT_HEX_NUMBER]
