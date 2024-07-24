
#ifndef flow_data_fdc08c49
#define flow_data_fdc08c49

#include <cstdint>
#include <map>

#include <flow/flow_data.h>

namespace dhcp_option {

class FlowData : public snort::FlowData {
  struct Entry {
    size_t offset;
    size_t size;
  };
  std::map<uint8_t, Entry> map;

public:
  FlowData(snort::Inspector *);
  unsigned static get_id();
  bool set(uint8_t type, size_t offset,
           size_t size);  // Will return false if entry already set
  bool has(uint8_t type); // Will return true if option "type" is stored
  bool get(uint8_t type, size_t &offset, size_t &size);
};

} // namespace dhcp_option
#endif
