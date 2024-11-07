#ifndef flow_data_8d10f3be
#define flow_data_8d10f3be

// This flow_data builds the LioLi that will be output by the alert plugin
// (alert_lioli)

// Snort includes
#include <flow/flow.h>
#include <flow/flow_data.h>

// System includes
#include <queue>
#include <string>
#include <variant>

// Local includes
#include "lioli.h"

namespace alert_lioli {

class FlowData : public snort::FlowData, public LioLi::Tree {
  // std::queue<std::variant<std::string, LioLi::Tree>> queue;

public:
  FlowData();
  unsigned static get_id();

  // void add(std::string &&text); // Adds a string to flow data
  // void add(LioLi::Tree &&tree); // Adds a Lioli tree to flow data

  static FlowData *get_from_flow(snort::Flow *flow);

  // friend LioLi::Tree &operator<<(LioLi::Tree &tree, FlowData &text);
};

} // namespace alert_lioli
#endif
