
#ifndef inspector_96b24c53
#define inspector_96b24c53

// Snort includes
#include <framework/inspector.h>
#include <framework/module.h>

// System includes

// Global includes

// Local includes

// Debug includes

namespace trout_wizard {

class Module;

class Inspector : public snort::Inspector {
private:
  Module &module;

public:
  Inspector(Module &module) : module(module) { assert(&module); };
  ~Inspector();

  void eval(snort::Packet *) override;

  snort::StreamSplitter *get_splitter(bool) override;

public:
  static snort::Inspector *ctor(snort::Module *module);
  static void dtor(snort::Inspector *p);
};

} // namespace trout_wizard

#endif // inspector_96b24c53
