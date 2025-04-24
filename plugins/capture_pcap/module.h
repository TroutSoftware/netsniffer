#ifndef module_23669415
#define module_23669415

// Snort includes

// System includes

// Global includes
#include <log_framework.h>

// Local includes

namespace capture_pcap {

struct Settings {
  std::shared_ptr<LioLi::Logger> logger;

public:
  std::string logger_name;
  int snaplen;    // libpcap snap lenght that should be used
  bool optimize_filter;

  LioLi::Logger &get_logger();
};

// This must match the s_pegs[] array
struct PegCounts {
  PegCount pkg_processed = 0;
  PegCount pkg_logged = 0;
  PegCount compiled_filters = 0;
};

class Module : public snort::Module {
  Settings settings;

  Module();

  Usage get_usage() const override;

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override;

  const PegInfo *get_pegs() const override;

  PegCount *get_counts() const override;


public:
  Settings &get_settings();
  PegCounts &get_peg_counts();

  static snort::Module *ctor() { return new Module(); }
  static void dtor(snort::Module *p) { delete p; }
};

} // namespace capture_pcap

#endif // #ifndef module_23669415
