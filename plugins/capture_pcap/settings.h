#ifndef settings_d22993bb
#define settings_d22993bb

// Snort includes
#include <framework/value.h>

// System includes
#include <list>
#include <memory>
#include <optional>
#include <string>

// Global includes

// Local includes
#include "filter.h"
#include "pcap_dumper.h"

// Debug includes

namespace capture_pcap {

/*
capture_pcap = {
  snap_length = 4096,
  optimize_filter = true,
  rotate_limit = 5,
  map = { { filter = "net 161.35.18.220",
            hint_ip = "161.35.18.220",
            hint_port = "80",
            pcap_prefix = "MyFirstPrefix"
          },{
            filter = "net 1.1.1.1",
            pcap_prefix = "my_second_prefix"            
          }
        }
}
*/  

class Filter;
class PcapDumper;
class Module;

struct Settings {
  Settings(const char* module_name);

  // Settings for all map entries
  //std::string logger_name;
  int snaplen;    // libpcap snap lenght that should be used
  bool optimize_filter;
  unsigned rotate_limit;

  struct MapItem {
    std::unique_ptr<Filter> filter;       
    std::shared_ptr<PcapDumper> dumper;   // Multiple filters can dump to the same pcap
    std::optional<uint16_t> port;   
    std::optional<uint32_t> ip;           // p->ptrs.ip_api.get_dst()    
  };

  std::list<std::unique_ptr<MapItem>> map;   // This might be made more inteligent at a later time

private:
  friend Module;
  
  std::string module_name;

  bool begin(const char*, int);
  bool end(const char*, int);
  bool set(const char*, snort::Value &val);

  std::unique_ptr<MapItem> zero_item;
  std::unique_ptr<MapItem> current_item;

  void reset();   // Clears all settings to default values
};



}

#endif // #ifndef settings_d22993bb
