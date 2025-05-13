
// Snort includes
#include <packet_io/sfdaq.h>
#include <protocols/packet.h>

// System includes

// Global includes

// Local includes
#include "common.h"
#include "filter.h"
#include "module.h"

// Debug includes

namespace capture_pcap {

Filter::Filter(std::string &&filter_string, std::shared_ptr<Settings> settings,
               PegCounts &pegs)
    : settings(settings), pegs(pegs), filter_string(filter_string) {
  compile();
}

Filter::Filter(std::string &filter_string, Module &module)
    : settings(module.get_settings()), pegs(module.get_peg_counts()),
      filter_string(filter_string) {
  compile();
}

Filter::~Filter() {
  // Clean up
  if (compiled_valid) {
    pcap_freecode(&compiled);
    compiled_valid = false;
  }
}

void Filter::compile() {
  pcap_t *dead = pcap_open_dead(DLT_EN10MB, settings->snaplen);
  if (pcap_compile(dead, &compiled, filter_string.c_str(),
                   settings->optimize_filter, PCAP_NETMASK_UNKNOWN)) {
    compiled_valid = false;
    snort::ErrorMessage(
        "ERROR: pcap compile returns \"%s\" when given \"%s\" as input\n",
        pcap_geterr(dead), filter_string.c_str());
  } else {
    compiled_valid = true;
    pegs.compiled_filters++;
  }
  pcap_close(dead);
}

bool Filter::is_valid() { return compiled_valid; }

bool Filter::match(snort::Packet *p) {
  pegs.pkg_evaluated++;

  const uint8_t *filter_pkt = p->pkt;
  uint32_t filter_pkt_len = p->pktlen;
  uint32_t filter_pkth_len = p->pkth->pktlen;

  if (bpf_filter(compiled.bf_insns, filter_pkt, filter_pkt_len,
                 filter_pkth_len)) {
    pegs.pkg_matched++;
    return true;
  }

  return false;
}

} // namespace capture_pcap
