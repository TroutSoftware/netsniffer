#ifndef inspector_[RANDOM_32BIT_HEX_NUMBER]
#define inspector_ [RANDOM_32BIT_HEX_NUMBER]

// Snort includes
#include <framework/inspector.h>

// System includes
#include <memory>

// Global includes

// Local includes

// Debug includes

namespace my_plugin_name {
class Module;
class Settings;

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

} // namespace my_plugin_name

#endif // inspector_[RANDOM_32BIT_HEX_NUMBER]
