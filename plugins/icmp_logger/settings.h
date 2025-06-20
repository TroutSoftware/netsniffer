#ifndef settings_eeb7e78e
#define settings_eeb7e78e

// Snort includes

// System includes
#include <cstdint>
#include <memory>

// Global includes
#include <log_framework.h>

// Local includes

// Debug includes

namespace icmp_logger {

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

} // namespace icmp_logger

#endif // #ifndef settings_eeb7e78e
