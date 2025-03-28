// Snort includes
#include <framework/decode_data.h>

// System includes

// Local includes
#include "inspector.h"
#include "module.h"
#include "plugin_def.h"

namespace trout_wizard {
namespace {

static const char *s_name = "trout_wizard";
static const char *s_help = "detects protocols";

static const snort::Parameter module_params[] = {
    {"logger", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Set logger output should be sent to"},
    {"concatenate", snort::Parameter::PT_BOOL, nullptr, "false",
     "Set to true if chunks should be concatenated"},
    {"split_size", snort::Parameter::PT_INT, "0:max31", "253",
     "How much data can be packed in each chunk from each direction"},
    {"pack_data", snort::Parameter::PT_BOOL, nullptr, "false",
     "Set to false if you only want unidirectional data in each chunk"},
    {"tag", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Adds $.tag to logs and sets the value of it"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

const PegInfo s_pegs[] = {
    {CountType::SUM, "packets processed", "Number of packages processed"},
    {CountType::SUM, "services detected", "Number of services detected"},
    {CountType::END, nullptr, nullptr}};

// TODO: actually increase these:
// This must match the s_pegs[] array
struct PegCounts {
  PegCount pkg_processed = 0;
  PegCount srv_detected = 0;
};

THREAD_LOCAL struct PegCounts s_peg_counts;

// Compile time sanity check of number of entries in s_pegs and s_peg_counts
static_assert(
    (sizeof(s_pegs) / sizeof(PegInfo)) - 1 ==
        sizeof(PegCounts) / sizeof(PegCount),
    "Entries in s_pegs doesn't match number of entries in s_peg_counts");

} // namespace

LioLi::Logger &Settings::get_logger() {
  if (!logger) {
    logger = LioLi::LogDB::get<LioLi::Logger>(logger_name.c_str());
  }
  return *logger;
}

Module::Module()
    : snort::Module(s_name, s_help, module_params), settings(new Settings) {}

Module::Usage Module::get_usage() const {
  return DETECT; /* GLOBAL, CONTEXT, INSPECT, DETECT */
}

bool Module::set(const char *, snort::Value &val, snort::SnortConfig *) {
  if (val.is("logger") && val.get_as_string().size() > 0) {
    settings->logger_name = val.get_string();
  } else if (val.is("concatenate")) {
    settings->concatenate = val.get_bool();
  } else if (val.is("pack_data")) {
    settings->pack_data = val.get_bool();
  } else if (val.is("split_size")) {
    settings->split_size = val.get_uint32();
  } else if (val.is("tag") && val.get_as_string().size() > 0) {
    settings->tag = val.get_string();
  } else {
    // fail if we didn't get something valid
    return false;
  }

  return true;
}

const PegInfo *Module::get_pegs() const { return s_pegs; }

PegCount *Module::get_counts() const {
  return reinterpret_cast<PegCount *>(&s_peg_counts);
}

bool Module::is_bindable() const { return true; }

std::shared_ptr<Settings> Module::get_settings() { return settings; }

const snort::InspectApi inspect_api = {
    {PT_INSPECTOR, sizeof(snort::InspectApi), INSAPI_VERSION, 0, API_RESERVED,
     API_OPTIONS, s_name, s_help, Module::ctor, Module::dtor},
    //      snort::IT_WIZARD, // snort::IT_PACKET (217, 216), snort::IT_WIZARD
    //      (87, 87),

    //      snort::IT_PASSIVE,  // (  0,   0)config only, or data consumer (eg
    //      file_log, binder, ftp_client)
    snort::IT_WIZARD, // ( 87,  87)-(114, 114) guesses service inspector
                      // paff = false 130 packages 12726 bytes
                      // paff = true  114 packages 10962 bytes
                      // payload is payload of UDP/TCP layer
    //    snort::IT_PACKET,   // (217, 216) processes raw packets only (eg
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

} // namespace trout_wizard
