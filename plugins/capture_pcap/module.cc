// Snort includes
#include <framework/decode_data.h>

// System includes
#include <string.h>   // For working on C style strings

// Local includes
#include "filter.h"
#include "inspector.h"
#include "module.h"
#include "pcap_dumper.h"
#include "plugin_def.h"

// Debug includes

namespace capture_pcap {
namespace {

static const char *s_name = "capture_pcap";
static const char *s_help = "filters network trafic and stores it in pcap files";


static const snort::Parameter map_item[] = {
    {"filter", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Filter strinng, for format see https://www.tcpdump.org/manpages/pcap-filter.7.html"},
    {"hint_ip", snort::Parameter::PT_IP4, nullptr, nullptr,
     "IPv4 address in the format aaa.bbb.ccc.ddd that might be matched before the filter"},
    {"hint_port", snort::Parameter::PT_INT, "0:65535", nullptr,
     "Port number that might be matched before the filter"},
    {"pcap_prefix", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Prefix for pcap file that will be written, it will be extended by \"[timestamp].pcap\""},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}
};

static const snort::Parameter module_params[] = {
    {"snap_length", snort::Parameter::PT_INT, "0:max31", "65536",
     "The snap length used when processing pacages (i.e. max size we process per package)"},
    {"testmode", snort::Parameter::PT_BOOL, nullptr, "false",
     "if set to true it will give consistent output, like using fixed "
     "timestamps"},
    {"optimize_filter", snort::Parameter::PT_BOOL, nullptr, "true",
     "Set the true if pcap filters should be optimized, false if not"},
    {"rotate_limit", snort::Parameter::PT_INT, "0:max31", "2147483647",
     "Set the limit of data writen to each pcap, 0 = no limit"},
    {"map", snort::Parameter::PT_LIST, map_item, nullptr,
     "Map with rules and pcap file prefixes, if a packet matches a rule, it will be written to the pcap"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}
};

const PegInfo s_pegs[] = {
    {CountType::SUM, "packets processed", "Number of packages processed"},
    {CountType::SUM, "packets logged", "Number of packages logged"},
    {CountType::SUM, "compiled_filters", "Number of bpf filters succesfully compiled"},
    {CountType::SUM, "packets evaluated", "Number of packages evaluated (by filter)"},
    {CountType::SUM, "packets matched", "Number of packages matched by filter"},
    {CountType::SUM, "packets written", "Number of packages written to pcap"},
    {CountType::END, nullptr, nullptr}
};

// TODO: Understand the pegs in a threaded context...
/*THREAD_LOCAL*/ struct PegCounts s_peg_counts;


// Compile time sanity check of number of entries in s_pegs and s_peg_counts
static_assert(
    (sizeof(s_pegs) / sizeof(PegInfo)) - 1 ==
        sizeof(PegCounts) / sizeof(PegCount),
    "Entries in s_pegs doesn't match number of entries in s_peg_counts");

} // namespace

Module::Module()
    : snort::Module(s_name, s_help, module_params), settings(std::make_shared<Settings>(s_name, s_peg_counts)) {
}

Module::~Module() {
  settings.reset();  // Will gracefully kill all workers from the pcap writers
}

bool Module::begin(const char* s, int i, snort::SnortConfig*) {
  return settings->begin(s,i);
}

bool Module::end(const char* s, int i, snort::SnortConfig*) {
  return settings->end(s, i);
}


bool Module::set(const char *s, snort::Value &val, snort::SnortConfig *) {
  return settings->set(s, val);
}

Module::Usage Module::get_usage() const {
  return INSPECT;
}

const PegInfo *Module::get_pegs() const {
  return s_pegs;
}

PegCount *Module::get_counts() const {
  return reinterpret_cast<PegCount *>(&s_peg_counts);
}

PegCounts &Module::get_peg_counts() {
  return s_peg_counts;
}

std::shared_ptr<Settings> Module::get_settings() { return settings; }

const snort::InspectApi inspect_api = {
    {PT_INSPECTOR, sizeof(snort::InspectApi), INSAPI_VERSION, 0, API_RESERVED,
     API_OPTIONS, s_name, s_help, Module::ctor, Module::dtor},
    snort::IT_PACKET,

    PROTO_BIT__ALL, // PROTO_BIT__ANY_PDU,
    nullptr,        // buffers
    nullptr,        // service
    nullptr,        // init
    nullptr,        // term
    nullptr,        // tinit
    nullptr,        // tterm
    Inspector::ctor,
    Inspector::dtor,
    nullptr, // ssn
    nullptr  // reset
};

} // namespace capture_pcap
