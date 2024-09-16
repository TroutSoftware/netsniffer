#ifndef trout_netflow_data_67f51d4a
#define trout_netflow_data_67f51d4a

// Snort includes
#include <flow/flow.h>
#include <flow/flow_data.h>
#include <protocols/packet.h>

// System includes
#include <memory>

// Local includes
#include "lioli.h"
#include "log_framework.h"

namespace trout_netflow {

class FlowData : public snort::FlowData {
  std::shared_ptr<LioLi::LogLioLiTree> logger;

  LioLi::Tree root = {"$"};

  bool first_pkt = true;

  uint64_t pkt_sum = 0;
  uint64_t payload_sum = 0;

public:
  FlowData(std::shared_ptr<LioLi::LogLioLiTree>);
  ~FlowData();
  unsigned static get_id();

  static FlowData *get_from_flow(snort::Flow *flow,
                                 std::shared_ptr<LioLi::LogLioLiTree> logger);

  void process(snort::Packet *);
};

} // namespace trout_netflow
#endif
