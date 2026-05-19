#ifndef inspector_221c56bd
#define inspector_221c56bd

// Snort includes
#include <framework/inspector.h>

// System includes
#include <memory>

// Global includes

// Local includes

// Debug includes

namespace icmp_logger {
class Module;
class Settings;

class Inspector : public snort::Inspector {
private:
  std::shared_ptr<Settings> settings;

  void eval(snort::Packet *) override;

  void log_unreachable(const snort::icmp::ICMPHdr &);

public:
  Inspector(Module *module);
  ~Inspector();

  static snort::Inspector *ctor(snort::Module *module);
  static void dtor(snort::Inspector *p) { delete p; }
};

} // namespace icmp_logger

#endif // inspector_221c56bd
