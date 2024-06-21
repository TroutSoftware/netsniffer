
#ifndef flow_data_fdc08c49
#define flow_data_fdc08c49

#include <flow/flow_data.h>

namespace dhcp_option {

class FlowData : public snort::FlowData {

public:
  FlowData(snort::Inspector *);
  unsigned static get_id();
};

} // namespace dhcp_option
#endif
