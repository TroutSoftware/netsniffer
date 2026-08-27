#ifndef client_id_monitor_92a27edc
#define client_id_monitor_92a27edc


// Snort includes
#include<sfip/sf_ip.h>

// System includes
#include<algorithm>
#include<map>
#include<memory>
#include<shared_mutex>
#include<span>
#include<stdint.h>
#include<vector>

// Global includes


// Local includes

// Debug includes

namespace mqtt_plugin {

class ClientIDMonitor {
  uint32_t min_size = 1;
  //std::shared_ptr<Settings> settings;

  // We need our own compare func for the maps so we don't need to
  // create vectors to do the lookup
  struct CompareFunc {
    using is_transparent = void;  // Tells std::map that find can take
                                  // any type the operator() can take

    template<class A, class B>
    bool operator()(const A &a, const B &b) const {
      return std::ranges::lexicographical_compare(a, b);
    }
  };

  std::shared_mutex mutex;    // Mutex is shared to allow multiple reads of the maps
  std::map<std::vector<uint8_t>, snort::SfIp, CompareFunc> map_current;
  std::map<std::vector<uint8_t>, snort::SfIp, CompareFunc> map_previous;
public:
  //ClientIDMonitor(std::shared_ptr<Settings> settings);
  ClientIDMonitor(uint32_t min_size);

  // True if unique, false if not
  bool check(const std::span<const uint8_t> &client_id, snort::SfIp &sf_ip);

};

} // namespace mqtt_plugin

#endif // #ifndef client_id_monitor_92a27edc
