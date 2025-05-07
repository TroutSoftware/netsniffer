
// Snort includes


// System includes

// Global includes

// Local includes
#include "common.h"

// Debug includes

namespace capture_pcap {


// The following function is copied from snorts packet_capture plugin    
int get_dlt() {
  int dlt = snort::SFDAQ::get_base_protocol();
  if (dlt == DLT_USER1)
      return DLT_EN10MB;
  return dlt;
}

} // namespace capture_pcap
