//
// This file contains the exported list of plugins from this module
//

#include <framework/inspector.h>

#include "inspector.h"
#include "ips_option.h"

SO_PUBLIC const snort::BaseApi *snort_plugins[] = {
    &dhcp_option::inspector.base, &dhcp_option::ips_option.base, nullptr};
