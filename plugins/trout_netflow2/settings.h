#ifndef settings_dc4a83d5
#define settings_dc4a83d5

// Snort includes

// System includes

// Global includes
#include <log_framework.h>

// Local includes

// Debug includes

namespace trout_netflow2 {

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

} // namespace trout_netflow2

#endif // #ifndef settings_dc4a83d5
