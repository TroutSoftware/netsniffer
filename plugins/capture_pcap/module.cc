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
#include <iostream>

namespace capture_pcap {
namespace {

static const char *s_name = "capture_pcap";
static const char *s_help = "filters network trafic and stores it in pcap files";


/*
capture_pcap = {
  snap_length = 4096,
  optimize_filter = true,
  rotate_limit = 5,
  map = { { filter = "net 161.35.18.220",
            hint_ip = "161.35.18.220",
            hint_port = "80",
            pcap_prefix = "MyFirstPrefix"
          },{
            filter = "net 1.1.1.1",
            pcap_prefix = "my_second_prefix"            
          }
        }
}
*/            
          

static const snort::Parameter map_item[] = {
    {"filter", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Filter strinng, for format see https://www.tcpdump.org/manpages/pcap-filter.7.html"},
    {"hint_ip", snort::Parameter::PT_STRING, nullptr, nullptr,
     "IPv6 address in the format aaa.bbb.ccc.ddd that might be matched before the filter"},
    {"hint_port", snort::Parameter::PT_INT, "0:65535", nullptr,
     "Port number that might be matched before the filter"},
    {"pcap_prefix", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Prefix for pcap file that will be written, it will be extended by \"[timestamp].pcap\""},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}
};
  


static const snort::Parameter module_params[] = {
    {"snap_length", snort::Parameter::PT_INT, "0:max31", "65536",
     "The snap length used when processing pacages (i.e. max size we process per package)"},
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

/*
LioLi::Logger &Settings::get_logger() {
  if (!logger) {
    logger = LioLi::LogDB::get<LioLi::Logger>(logger_name.c_str());
  }
  return *logger;
}
*/

Module::Module()
    : snort::Module(s_name, s_help, module_params), settings(std::make_shared<Settings>(s_name)) {
}

Module::~Module() {
}

bool Module::begin(const char* s, int i, snort::SnortConfig*) {
  return settings->begin(s,i);
/*  
  std::cout << "MKRTEST: begin called on \"" << s << "\" index:" << i << std::endl;
  
  // Check if this is a fresh load of settings
  if (0 == strcmp(s, s_name)) {
    settings->map.clear();
    return true;
  }

  return false;
*/
}

bool Module::end(const char* s, int i, snort::SnortConfig*) {
  return settings->end(s, i);
  /*
  std::cout << "MKRTEST: end called on \"" << s << "\" index:" << i << std::endl;
  return true;
  */
}


bool Module::set(const char *s, snort::Value &val, snort::SnortConfig *) {
  return settings->set(s, val);
/*  
  std::cout << "MKRTEST: set(\"" << s << "\", \"" << val.get_name() << "\", ...)" << std::endl;
  if (val.is("snap_length")) {
    settings->snaplen = val.get_int32();
  } else if (val.is("optimize_filter")) {
    settings->optimize_filter = val.get_bool();
  } else if (val.is("rotate_limit")) {
    settings->rotate_limit = val.get_int32();
  } else {
    // fail if we didn't get something valid
    return false;
  }

  return true;
*/  
}

Module::Usage Module::get_usage() const {
  return INSPECT; /* GLOBAL, CONTEXT, INSPECT, DETECT */
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
    //      snort::IT_WIZARD, // snort::IT_PACKET (217, 216), snort::IT_WIZARD
    //      (87, 87),

    //      snort::IT_PASSIVE,  // (  0,   0)config only, or data consumer (eg
    //      file_log, binder, ftp_client)
    //snort::IT_WIZARD, // ( 87,  87)-(114, 114) guesses service inspector
                      // paff = false 130 packages 12726 bytes
                      // paff = true  114 packages 10962 bytes
                      // payload is payload of UDP/TCP layer
    snort::IT_PACKET,   // (217, 216) processes raw packets only (eg
    //    normalize, capture) snort::IT_STREAM,   // (217,   0) (if configured
    //    as the GLOBAL flow tracker, otherwise (0,0) flow tracking and
    //    reassembly (eg ip, tcp, udp) snort::IT_FIRST,    // ( 41,  40) analyze
    //    1st pkt of new flow and 1st pkt after reload of ongoing flow (eg rep)
    //    snort::IT_NETWORK,  // (234, 233)-(231, 230) process packets w/o
    //    service (eg arp, bo) snort::IT_SERVICE,  // (  0,   0) extract and
    //    analyze service PDUs (eg dce, http, ssl) snort::IT_CONTROL,  // (235,
    //    234)-(230, 229) process all packets before detection (eg appid)
    //    snort::IT_PROBE,    // (294, 233)-(290, 229) process all packets after
    //    detection (eg perf_monitor, port_scan)
    //   payload is TCP layer
    //    snort::IT_FILE,     // CORE DUMP file identification inspector
    //    snort::IT_PROBE_FIRST, // (295, 18)-(291,  14) process all packets
    //    before detection (eg packet_capture)
    //   payload is TCP layer
    //    snort::IT_MAX

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
