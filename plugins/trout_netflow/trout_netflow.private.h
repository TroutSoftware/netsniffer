#ifndef trout_netflow_private_e55ebe42
#define trout_netflow_private_e55ebe42

// Snort includes
#include <framework/counts.h>

// System includes
#include <memory>

// Local includes
#include "log_framework.h"

namespace trout_netflow {

// This must match the s_pegs[] array
struct PegCounts {
  PegCount pkg_processed = 0;
  PegCount srv_detected = 0;
  PegCount pkt_size = 0;
  PegCount payload_size = 0;
};

// This must match the s_pegs[] array
extern THREAD_LOCAL struct PegCounts s_peg_counts;

// Structure module level settings are transferred in
struct Settings {
  std::shared_ptr<LioLi::LogLioLiTree> logger;

public:
  std::string logger_name;
  bool testmode = false;

  std::shared_ptr<LioLi::LogLioLiTree> get_logger() {
    if (!logger) {
      logger = LioLi::LogDB::get<LioLi::LogLioLiTree>(logger_name.c_str());
    }
    return logger;
  }
};

} // namespace trout_netflow

#endif // #ifndef trout_netflow_private_e55ebe42
