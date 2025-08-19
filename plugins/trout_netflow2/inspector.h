#ifndef inspector_efe8d555
#define inspector_efe8d555

// Snort includes
#include <framework/inspector.h>

// System includes
#include <memory>

// Global includes

// Local includes
#include "cache.h"

// Debug includes

namespace trout_netflow2 {
class Module;
class Settings;

class Inspector : public snort::Inspector {
private:
  std::shared_ptr<Settings> settings;
  std::shared_ptr<Cache> cache;

  void eval(snort::Packet *) override;

public:
  Inspector(Module *module);
  ~Inspector();

  static snort::Inspector *ctor(snort::Module *module);
  static void dtor(snort::Inspector *p);
};

} // namespace trout_netflow2

#endif // inspector_efe8d555
