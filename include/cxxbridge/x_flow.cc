#include "flow/flow.h"
#include <string>

namespace xsnort {

const char *get_service(const snort::Flow &flow) {
  assert(flow.service);
  return flow.service;
}

} // namespace xsnort
