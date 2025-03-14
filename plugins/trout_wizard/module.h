#ifndef module_1d34881e
#define module_1d34881e

// Snort includes

// System includes

// Global includes
#include <log_framework.h>

// Local includes

namespace trout_wizard {

struct Settings {
  std::shared_ptr<LioLi::Logger> logger;

public:
  std::string logger_name;
  bool concatenate = false;
  bool pack_data = false;
  uint32_t split_size = 253;

  LioLi::Logger &get_logger();
};

class Module : public snort::Module {
  std::shared_ptr<Settings> settings;

  Module();

  Usage get_usage() const override;

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override;

  const PegInfo *get_pegs() const override;

  PegCount *get_counts() const override;

  bool is_bindable() const override;

public:
  std::shared_ptr<Settings> get_settings();

  static snort::Module *ctor() { return new Module(); }
  static void dtor(snort::Module *p) { delete p; }
};

} // namespace trout_wizard

#endif // #ifndef module_1d34881e
