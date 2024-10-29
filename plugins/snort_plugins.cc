//
// This file contains the exported list of plugins from this module
//

// Snort includes
#include <framework/inspector.h>

// System includes

// Local includes
#include "alert_lioli/alert_lioli.h"
#include "alert_lioli/ips_lioli_bind.h"
#include "alert_lioli/ips_lioli_tag.h"
#include "dhcp_monitor/inspector.h"
#include "dhcp_option/inspector.h"
#include "dhcp_option/ips_option.h"
#include "dhcp_option/ips_option_ip_filter.h"
#include "log/log_bill.h"
#include "log/log_lorth.h"
#include "log/log_null.h"
#include "log/log_txt.h"
#include "log/output_to_file.h"
#include "log/output_to_pipe.h"
#include "log/output_to_stdout.h"
#include "trout_netflow/trout_netflow.h"

// clang-format off
SO_PUBLIC const snort::BaseApi *snort_plugins[] = {
  &alert_lioli::log_api.base,
  &dhcp_monitor::dhcpmonitor_api.base,
  &dhcp_option::inspector.base,
  &dhcp_option::ips_option.base,
  &ip_filter::ips_option.base,
  &ips_lioli_bind::ips_option.base,
  &ips_lioli_tag::ips_option.base,
  &log_bill::inspect_api.base,
  &log_lorth::inspect_api.base,
  &log_null::inspect_api.base,
  &log_txt::inspect_api.base,
  &output_to_file::inspect_api.base,
  &output_to_pipe::inspect_api.base,
  &output_to_stdout::inspect_api.base,
  &trout_netflow::inspect_api.base,

  nullptr
};
// clang-format on
