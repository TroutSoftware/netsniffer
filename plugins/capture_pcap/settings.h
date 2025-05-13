#ifndef settings_d22993bb
#define settings_d22993bb

// Snort includes
#include <framework/value.h>

// System includes
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <string>

// Global includes

// Local includes
#include "filter.h"
#include "pcap_dumper.h"

// Debug includes

namespace capture_pcap {

class Filter;
class PcapDumper;
class Module;

struct Settings : std::enable_shared_from_this<Settings> {
  PegCounts &pegs;
  Settings(const char* module_name, PegCounts &pegs);

  // Settings for all map entries
  int snaplen;    // libpcap snap lenght that should be used
  bool testmode;
  bool optimize_filter;
  unsigned rotate_limit;

  struct MapItem {
    std::unique_ptr<Filter> filter;
    std::shared_ptr<PcapDumper> dumper;   // Multiple filters can dump to the same pcap
    std::optional<uint16_t> port;
    std::optional<uint32_t> ip;
  };

  std::list<std::unique_ptr<MapItem>> map;   // This might be made more inteligent at a later time
  std::map<std::string, std::weak_ptr<PcapDumper>> dumper_map;

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
