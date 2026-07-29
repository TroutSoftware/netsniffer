#ifndef inspector_8F24C6A1
#define inspector_8F24C6A1

// Snort includes
#include <framework/inspector.h>

// System includes
#include <memory>
#include <string>

// Global includes

// Local includes

// Debug includes

namespace mqtt_plugin {
class Module;
class Settings;

class Inspector : public snort::Inspector {
private:
  std::shared_ptr<Settings> settings;

  void eval(snort::Packet *) override;

  snort::StreamSplitter* get_splitter(bool to_server) override;

  // Used to reject the packet as being MQTT
  void reject(snort::Packet *, std::string reason);

public:
  Inspector(Module *module);
  ~Inspector();

  static snort::Inspector *ctor(snort::Module *module);
  static void dtor(snort::Inspector *p);
};

} // namespace mqtt_plugin

#endif // #ifndef inspector_8F24C6A1
