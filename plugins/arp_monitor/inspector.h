#ifndef inspector_72f451c3
#define inspector_72f451c3

// Snort includes
#include <framework/inspector.h>
#include <framework/module.h>

// System includes

// Global includes

// Local includes
#include "module.h"

// Debug includes

namespace arp_monitor {

class Inspector : public snort::Inspector {
private:
  //  std::shared_ptr<Settings> settings;
  //  PegCounts &pegs;

public:
  Inspector(Module &module);
  ~Inspector();

  void eval(snort::Packet *) override;

public:
  static snort::Inspector *ctor(snort::Module *module) {
    return new Inspector(*dynamic_cast<Module *>(module));
  }

  static void dtor(snort::Inspector *p) { delete p; }
};

} // namespace arp_monitor

#endif // inspector_0d4fd9ba
