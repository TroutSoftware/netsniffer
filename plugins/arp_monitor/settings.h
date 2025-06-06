#ifndef settings_3ed8ddda
#define settings_3ed8ddda

// Snort includes

// System includes
#include <cstdint>
#include <memory>

// Global includes
#include <log_framework.h>

// Local includes

// Debug includes

namespace arp_monitor {

class module;

struct Settings {
  friend module;

  std::string logger_name;
  std::shared_ptr<LioLi::Logger> logger;
  uint32_t timeout_ms;

public:
  uint32_t get_timeout_ms();
  LioLi::Logger &get_logger();
};

} // namespace arp_monitor

#endif // #ifndef settings_3ed8ddda
