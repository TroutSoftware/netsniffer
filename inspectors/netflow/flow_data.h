#ifndef flow_data_8d10f3be
#define flow_data_8d10f3be

#include <string>

#include <flow/flow_data.h>

namespace NetFlow {

class FlowData : public snort::FlowData {

public:
  FlowData();
  unsigned static get_id();
  std::string lioli;
};

} // namespace NetFlow
#endif
