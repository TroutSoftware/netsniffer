
#ifndef inspector_0d4fd9ba
#define inspector_0d4fd9ba

// Snort includes
#include <framework/inspector.h>
#include <framework/module.h>

// System includes

// Global includes

// Local includes

// Debug includes

namespace capture_pcap {

class Module;

class Inspector : public snort::Inspector {
private:
  Module &module;

public:
  Inspector(Module &module) : module(module) { assert(&module); };
  ~Inspector();

  void eval(snort::Packet *) override;

public:
  static snort::Inspector *ctor(snort::Module *module);
  static void dtor(snort::Inspector *p);
};

} // namespace capture_pcap

#endif // inspector_0d4fd9ba
