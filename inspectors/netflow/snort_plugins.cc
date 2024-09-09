//
// This file contains the exported list of plugins from this module
//

#include <framework/inspector.h>

#include "alert_lioli.h"
#include "ips_lioli_bind.h"
#include "log_lorth.h"
#include "log_txt.h"
#include "output_to_file.h"
#include "output_to_pipe.h"
#include "output_to_stdout.h"

// clang-format off
SO_PUBLIC const snort::BaseApi *snort_plugins[] = {
    &alert_lioli::log_api.base,
    &ips_lioli_bind::ips_option.base,
    &log_lorth::inspect_api.base,
    &output_to_file::inspect_api.base,
    &output_to_pipe::inspect_api.base,
    &output_to_stdout::inspect_api.base,
    &log_txt::inspect_api.base,
    nullptr};
// clang-format on
