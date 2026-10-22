#ifndef inspector_E7A60A65
#define inspector_E7A60A65

// Snort includes
#include <framework/inspector.h>

// System includes
#include <memory>

// Global includes

// Local includes
#include "module.h"
#include "settings.h"

// Debug includes

namespace bacnet_ip {

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

} // namespace bacnet_ip

#endif // inspector_E7A60A65
