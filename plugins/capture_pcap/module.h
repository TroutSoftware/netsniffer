#ifndef module_23669415
#define module_23669415

// Snort includes
#include <framework/counts.h>
#include <framework/module.h>

// System includes
#include <memory>
// #include <optional>

// Global includes
#include <log_framework.h>

// Local includes

namespace capture_pcap {

class Settings;

// This must match the s_pegs[] array
struct PegCounts {
  PegCount pkg_processed = 0;
  PegCount pkg_logged = 0;
  PegCount compiled_filters = 0;
  PegCount pkg_evaluated = 0;
  PegCount pkg_matched = 0;
  PegCount pkg_written = 0;
};

class Module : public snort::Module {
  std::shared_ptr<Settings>
      settings; // Settings is a shared ptr as users of the settings migh live
                // longer than the module

  Module();
  ~Module();

  bool begin(const char *, int, snort::SnortConfig *) override;
  bool end(const char *, int, snort::SnortConfig *) override;

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override;

  Usage get_usage() const override;

  const PegInfo *get_pegs() const override;

  PegCount *get_counts() const override;

public:
  std::shared_ptr<Settings> get_settings();
  // TODO: Solve the threading mystery (for now it is ignored)
  PegCounts &get_peg_counts();

  static snort::Module *ctor() { return new Module(); }
  static void dtor(snort::Module *p) { delete p; }
};

} // namespace capture_pcap

#endif // #ifndef module_23669415
