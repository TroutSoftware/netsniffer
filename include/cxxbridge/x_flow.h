#pragma once
#include "flow/flow.h"
#include <string>

namespace xsnort {

const char *get_service(const snort::Flow &flow);

} // namespace xsnort
