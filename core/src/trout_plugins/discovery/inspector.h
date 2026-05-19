#ifndef inspector_5E87A41B
#define inspector_5E87A41B

// Snort includes
#include <daq_common.h>
#include <framework/inspector.h>

// System includes
#include <algorithm>
#include <memory>

// Global includes

// Local includes
#include "known_hash.h"
#include "settings.h"

// Debug includes

namespace trout::discovery {
class Module;

class Inspector : public snort::Inspector {
private:
  std::shared_ptr<Settings> settings;

  void eval(snort::Packet *) override;

  class {
  public:
    using KnownHashType = KnownHash<decltype(DAQ_PktHdr_t::flow_id)>;

  private:
    KnownHashType a, b;

    KnownHashType *active_table = &a;
    KnownHashType *passive_table = &b;

  public:
    KnownHashType &active() { return *active_table; }
    KnownHashType &passive() { return *passive_table; }
    void swap() { std::swap(active_table, passive_table); }
  } known_hash;

public:
  Inspector(Module *module);
  ~Inspector();

  static snort::Inspector *ctor(snort::Module *module);
  static void dtor(snort::Inspector *p);
};

} // namespace trout::discovery

#endif // inspector_5E87A41B
