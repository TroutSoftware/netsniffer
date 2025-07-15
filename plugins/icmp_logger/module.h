#ifndef module_68abd22b
#define module_68abd22b

// Snort includes
#include <framework/module.h>

// System includes

// Global includes

// Local includes
#include "settings.h"

// Debug includes

namespace icmp_logger {

class Module : public snort::Module {
  std::shared_ptr<Settings> settings = std::make_shared<Settings>();

  Module();
  ~Module();

  // Settings
  bool begin(const char *, int, snort::SnortConfig *) override;
  bool end(const char *, int, snort::SnortConfig *) override;
  bool set(const char *, snort::Value &val, snort::SnortConfig *) override;

  Usage get_usage() const override;

  unsigned get_gid() const override;
  const snort::RuleMap *get_rules() const override;

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

} // namespace icmp_logger

#endif // #ifndef module_68abd22b
