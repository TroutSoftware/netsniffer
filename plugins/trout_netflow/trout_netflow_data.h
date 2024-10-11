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
#include "trout_netflow.private.h"

namespace trout_netflow {

class FlowData : public snort::FlowData {
  Settings settings;

  LioLi::Tree root = {"$"};

  bool first_pkt = true;
  std::chrono::steady_clock::time_point first_pkt_time;

  struct PP {
    const char *name = "undefined";
    uint64_t packet = 0;
    uint64_t payload = 0;

    PP(const char *name) : name(name) {}
    PP(uint64_t packet, uint64_t payload) : packet(packet), payload(payload) {}

    void operator+=(PP &pp) {
      packet += pp.packet;
      payload += pp.payload;
    }

    LioLi::Tree gen_tree() {
      LioLi::Tree tree(name);
      tree << (LioLi::Tree("packet") << packet)
           << (LioLi::Tree("payload") << payload);
      return tree;
    }

    void clear() {
      packet = 0;
      payload = 0;
    }

    bool is_significant_of(PP &other) const {
      return (packet > other.packet >> 3);
    }

    operator bool() const { return packet > 0 || payload > 0; }
  };

  // Todo: Check if this should be atomic
  PP acc = {"acc"};

  std::chrono::steady_clock::time_point delta_pkt_time;
  PP delta = {"delta"};

  LioLi::Tree gen_delta();

  void dump_delta();

public:
  FlowData(Settings &);
  ~FlowData();
  unsigned static get_id();

  static FlowData *get_from_flow(snort::Flow *flow, Settings &);

  void process(snort::Packet *);

  void set_service_name(const char *);
};

} // namespace trout_netflow
#endif
