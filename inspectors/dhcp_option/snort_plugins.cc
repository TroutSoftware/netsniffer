//
// This file contains the exported list of plugins from this module
//

#include <framework/inspector.h>

#include "inspector.h"
#include "ips_option.h"

SO_PUBLIC const BaseApi *snort_plugins[] = {&dhcp_option::inspector,
                                            &dhcp_option::ips_option,
                                            nullptr};
