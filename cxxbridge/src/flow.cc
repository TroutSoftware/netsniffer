#include "framework/data_bus.h"

#include <cassert>

namespace xsnort {
const char *flow_service(const snort::Flow &flow) {
    assert(&flow);

    if (flow.service) return flow.service;

    return "unspecified";
}

} // namespace xsnort


