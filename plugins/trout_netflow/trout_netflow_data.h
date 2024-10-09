#ifndef trout_netflow_data_67f51d4a
#define trout_netflow_data_67f51d4a

// Snort includes
#include <flow/flow.h>
#include <flow/flow_data.h>
#include <protocols/packet.h>

// System includes
#include <chrono>
#include <memory>
#include <string>

// Local includes
#include "lioli.h"
#include "log_framework.h"

namespace trout_netflow {

class FlowData : public snort::FlowData {
  std::shared_ptr<LioLi::LogLioLiTree> logger;

  LioLi::Tree root = {"$"};

  bool first_pkt = true;
  std::chrono::steady_clock::time_point first_pkt_time;

  // Todo: Check if this should be atomic
  uint64_t pkt_sum = 0;
  uint64_t payload_sum = 0;

  std::chrono::steady_clock::time_point delta_pkt_time;
  uint64_t pkt_delta = 0;
  uint64_t payload_delta = 0;

  void dump_delta();

public:
  FlowData(std::shared_ptr<LioLi::LogLioLiTree>);
  ~FlowData();
  unsigned static get_id();

  static FlowData *get_from_flow(snort::Flow *flow,
                                 std::shared_ptr<LioLi::LogLioLiTree> logger);

  void process(snort::Packet *);

  void set_service_name(const char *);
};

} // namespace trout_netflow
#endif
