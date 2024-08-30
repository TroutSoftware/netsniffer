//
// This file contains the exported list of plugins from this module
//

#include <framework/inspector.h>

#include "alert_lioli.h"
#include "ips_lioli_bind.h"
#include "log_lorth.h"
#include "log_txt.h"

SO_PUBLIC const snort::BaseApi *snort_plugins[] = {
    &alert_lioli::log_api.base, &ips_lioli_bind::ips_option.base,
    &log_lorth::inspect_api.base, &log_txt::inspect_api.base,

    nullptr};
