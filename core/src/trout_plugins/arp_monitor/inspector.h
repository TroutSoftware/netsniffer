#ifndef inspector_72f451c3
#define inspector_72f451c3

// Snort includes
#include <framework/inspector.h>

// System includes
#include <memory>

// Global includes

// Local includes

// Debug includes

namespace arp_monitor {
class Module;
class Settings;

class Inspector : public snort::Inspector {
private:
  class Worker;

  std::unique_ptr<Worker> worker;

  /*
    std::mutex req_list_mutex;  // Protects the request list
    struct ReqEntry;
    std::list<ReqEntry> req_list;


    // Removes entries from req_list, return true if something was removed
    bool remove_entries(const snort::arp::EtherARP *ah);
  */
  std::shared_ptr<Settings> settings;

  void eval(snort::Packet *) override;

public:
  Inspector(Module *module);
  ~Inspector();

  static snort::Inspector *ctor(snort::Module *module);
  static void dtor(snort::Inspector *p) { delete p; }
};

} // namespace arp_monitor

#endif // inspector_0d4fd9ba
