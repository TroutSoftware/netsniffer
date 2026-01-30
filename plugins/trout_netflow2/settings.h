#ifndef settings_dc4a83d5
#define settings_dc4a83d5

// Snort includes

// System includes

// Global includes
#include <log_framework.h>

// Local includes

// Debug includes

namespace trout_netflow2 {

class Module;

class Settings {
  friend Module;

  std::string logger_name;
  std::shared_ptr<LioLi::Logger> logger;
  bool testmode = false;
  bool do_ping = false;
  bool generate_service_map = false;
  bool extended_console_logging = false;
  uint32_t cache_size;
  uint32_t flush_interval_ms;
  uint32_t source_id;

public:
  LioLi::Logger &get_logger();
  bool get_testmode();
  bool get_do_ping();
  bool get_generate_service_map();
  bool get_extended_console_logging();
  uint32_t get_max_cache_size();
  uint32_t get_flush_interval_ms();
  uint32_t get_source_id();
  std::string get_logger_name();
};

} // namespace trout_netflow2

#endif // #ifndef settings_dc4a83d5
