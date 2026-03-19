#ifndef inspector_5E87A41B
#define inspector_5E87A41B

// Snort includes
#include <framework/inspector.h>

// System includes
#include <memory>

// Global includes

// Local includes
#include "settings.h"

// Debug includes

namespace trout::discovery {
class Module;

class Inspector : public snort::Inspector {
private:
  std::shared_ptr<Settings> settings;

  void eval(snort::Packet *) override;

public:
  Inspector(Module *module);
  ~Inspector();

  static snort::Inspector *ctor(snort::Module *module);
  static void dtor(snort::Inspector *p);
};

} // namespace trout::discovery

#endif // inspector_5E87A41B
