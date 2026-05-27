#ifndef settings_dc4a83d5
#define settings_dc4a83d5

// Snort includes
#include "parser/parse_ip.h"
#include "sfip/sf_ipvar.h"

// System includes
#include <memory>

// Global includes
#include "../includes/log_framework.h"

// Local includes

// Debug includes

namespace trout_netflow2 {

class Module;

class Settings {
  friend Module;

  std::string logger_name;
  std::shared_ptr<LioLi::Logger> logger = LioLi::Logger::get_null_obj();
  bool testmode = false;
  bool do_ping = false;
  bool generate_service_map = false;
  bool extended_console_logging = false;
  uint8_t undefined_ip_protocol_number;
  uint32_t cache_size;
  uint32_t flush_interval_ms;
  uint32_t template_resend_interval_s;
  uint32_t source_id;
  struct SfipDeleter {
    void operator()(sfip_var_t *p) const { sfvar_free(p); }
  };
  std::unique_ptr<sfip_var_t, SfipDeleter> exclude;

public:
  LioLi::Logger &get_logger();
  bool get_testmode();
  bool get_do_ping();
  bool get_generate_service_map();
  bool get_extended_console_logging();
  uint8_t get_undefined_ip_protocol_number();
  uint32_t get_max_cache_size();
  uint32_t get_flush_interval_ms();
  uint32_t get_template_resend_interval_s();
  uint32_t get_source_id();
  std::string get_logger_name();
  bool check_exclude(const snort::SfIp &ip_to_check);
};

} // namespace trout_netflow2

#endif // #ifndef settings_dc4a83d5
