
#ifndef inspector_0d4fd9ba
#define inspector_0d4fd9ba

// Snort includes
#include <framework/inspector.h>
#include <framework/module.h>

// System includes
#include <memory>

// Global includes

// Local includes
#include "filter.h"

// Debug includes

namespace capture_pcap {

class Module;

class Inspector : public snort::Inspector {
private:
  // TODO: The module WILL BE deleted before the inspector make this safe for all inspectors  
  Module &module;
  std::unique_ptr<Filter> filter;  // For testing purposes, DO NOT COMMIT!!!
public:
  //Inspector(Module &module) : module(module) { assert(&module); };
  Inspector(Module &module);
  ~Inspector();

  void eval(snort::Packet *) override;

public:
  static snort::Inspector *ctor(snort::Module *module);
  static void dtor(snort::Inspector *p);
};

} // namespace capture_pcap

#endif // inspector_0d4fd9ba
