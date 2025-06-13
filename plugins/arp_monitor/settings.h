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
  std::string missing_reply_alert_tag;
  std::shared_ptr<LioLi::Logger> logger;
  uint32_t timeout_ms;
  uint32_t max_req_queue;
  bool announcement_is_reply;
  bool testmode;

public:
  LioLi::Logger &get_logger();
  uint32_t get_timeout_ms();
  uint32_t get_max_req_queue();
  bool get_announcement_is_reply();
  std::string &get_missing_reply_alert_tag();
  bool get_testmode();
};

} // namespace arp_monitor

#endif // #ifndef settings_3ed8ddda
