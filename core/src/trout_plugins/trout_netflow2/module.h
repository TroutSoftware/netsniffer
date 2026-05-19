#ifndef module_c451803f
#define module_c451803f

// Snort includes
#include <framework/module.h>

// System includes

// Global includes

// Local includes
#include "settings.h"

// Debug includes

namespace trout_netflow2 {

class Module : public snort::Module {
  std::shared_ptr<Settings> settings = std::make_shared<Settings>();

  Module();
  ~Module();

  // Settings
  bool begin(const char *, int, snort::SnortConfig *) override;
  bool end(const char *, int, snort::SnortConfig *) override;
  bool set(const char *, snort::Value &val, snort::SnortConfig *) override;

  Usage get_usage() const override;

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

} // namespace trout_netflow2

#endif // #ifndef module_c451803f
