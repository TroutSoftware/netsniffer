#ifndef module_3B91DE57
#define module_3B91DE57

// Snort includes
#include <framework/module.h>

// System includes

// Global includes

// Local includes
#include "settings.h"

// Debug includes

namespace mqtt_plugin {

class Module : public snort::Module {
  std::shared_ptr<Settings> settings = std::make_shared<Settings>();

  Module();
  ~Module();

  // Settings
  bool begin(const char *, int, snort::SnortConfig *) override;
  bool end(const char *, int, snort::SnortConfig *) override;
  bool set(const char *, snort::Value &val, snort::SnortConfig *) override;

  Usage get_usage() const override;

  bool is_bindable() const override { return true; }

  // Pegs
  const PegInfo *get_pegs() const override;
  PegCount *get_counts() const override;

public:
  std::shared_ptr<Settings> get_settings();

  // PegCounts &get_peg_counts();
  static const char *get_module_name();
  static const char *get_module_help();

  static snort::Module *ctor() { return new Module(); }
  static void dtor(snort::Module *p) { delete p; }
};

} // namespace mqtt_plugin

#endif // #ifndef module_3B91DE57
