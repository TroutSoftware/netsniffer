//
// This file contains the exported list of plugins from this module
//

// Snort includes
#include <framework/inspector.h>

// System includes

// Local includes
#include "alert_lioli.h"
#include "ips_lioli_bind.h"
#include "log_bill.h"
#include "log_lorth.h"
#include "log_txt.h"
#include "output_to_file.h"
#include "output_to_pipe.h"
#include "output_to_stdout.h"
#include "trout_netflow.h"

// clang-format off
SO_PUBLIC const snort::BaseApi *snort_plugins[] = {
  &alert_lioli::log_api.base,
  &ips_lioli_bind::ips_option.base,
  &log_bill::inspect_api.base,
  &log_lorth::inspect_api.base,
  &log_txt::inspect_api.base,
  &output_to_file::inspect_api.base,
  &output_to_pipe::inspect_api.base,
  &output_to_stdout::inspect_api.base,
  &trout_netflow::inspect_api.base,

  nullptr
};
// clang-format on
