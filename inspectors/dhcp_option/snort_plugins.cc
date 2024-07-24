//
// This file contains the exported list of plugins from this module
//

#include <framework/inspector.h>

#include "inspector.h"
#include "ips_option.h"
#include "ips_option_ip_filter.h"

SO_PUBLIC const snort::BaseApi *snort_plugins[] = {
    &dhcp_option::inspector.base, &dhcp_option::ips_option.base,
    &ip_filter::ips_option.base, nullptr};
