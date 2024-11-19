
// Snort includes
#include <framework/data_bus.h>
#include <framework/decode_data.h>
#include <framework/inspector.h>
#include <framework/module.h>
#include <log/messages.h>
#include <pub_sub/intrinsic_event_ids.h>

// System includes
#include <cassert>

// Local includes
#include "log_framework.h"
#include "trout_netflow.h"
#include "trout_netflow.private.h"
#include "trout_netflow_data.h"

// Debug includes

namespace trout_netflow {

THREAD_LOCAL struct PegCounts s_peg_counts;

namespace {

static const char *s_name = "trout_netflow";
static const char *s_help = "generates netflow data to a lioli logger";

static const snort::Parameter module_params[] = {
    {"logger", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Set logger output should be sent to"},
    {"testmode", snort::Parameter::PT_BOOL, nullptr, "false",
     "if set to true it will give consistent output, like using fixed "
     "timestamps"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

const PegInfo s_pegs[] = {
    {CountType::SUM, "packets processed", "Number of packages processed"},
    {CountType::SUM, "services detected", "Number of services detected"},
    {CountType::SUM, "packets total size", "Sum of size of all packages"},
    {CountType::SUM, "payload total size", "Sum of size of all payloads"},
    {CountType::END, nullptr, nullptr}};

// Compile time sanity check of number of entries in s_pegs and s_peg_counts
static_assert(
    (sizeof(s_pegs) / sizeof(PegInfo)) - 1 ==
        sizeof(PegCounts) / sizeof(PegCount),
    "Entries in s_pegs doesn't match number of entries in s_peg_counts");

class Module : public snort::Module {
  Module() : snort::Module(s_name, s_help, module_params) {}

  Usage get_usage() const override { return INSPECT; }

  Settings settings;

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("logger") && val.get_as_string().size() > 0) {
      settings.logger_name = val.get_string();
    } else if (val.is("testmode")) {
      settings.testmode = val.get_bool();
    } else {
      // fail if we didn't get something valid
      return false;
    }

    return true;
  }

  const PegInfo *get_pegs() const override { return s_pegs; }

  PegCount *get_counts() const override {
    return reinterpret_cast<PegCount *>(&s_peg_counts);
  }

public:
  Settings &get_settings() { return settings; }

  static snort::Module *ctor() { return new Module(); }
  static void dtor(snort::Module *p) { delete p; }
};

class ServiceEventHandler : public snort::DataHandler {
  Settings settings;

public:
  ServiceEventHandler(Settings &settings)
      : DataHandler(s_name), settings(settings) {}

  void handle(snort::DataEvent &, snort::Flow *flow) override {
    s_peg_counts.srv_detected++;

    if (flow) {
      FlowData *data = FlowData::get_from_flow(flow, settings);
      assert(data);

      data->set_service_name(flow->service);
    }
  }
};

class Inspector : public snort::Inspector {
  Settings settings;

  Inspector(Module *module) {
    assert(module);

    settings = module->get_settings();
  }

  void eval(snort::Packet *pkt) override {
    s_peg_counts.pkg_processed++;

    if (pkt && pkt->flow) {
      FlowData *data = FlowData::get_from_flow(pkt->flow, settings);
      data->process(pkt);
    } else {
      FlowData tmp(settings);
      tmp.process(pkt);
    }
  };

  bool configure(snort::SnortConfig *) {
    snort::DataBus::subscribe_network(
        snort::intrinsic_pub_key, snort::IntrinsicEventIds::FLOW_SERVICE_CHANGE,
        new ServiceEventHandler(settings));
    return true;
  }

public:
  static snort::Inspector *ctor(snort::Module *module) {
    return new Inspector(dynamic_cast<Module *>(module));
  }

  static void dtor(snort::Inspector *p) { delete dynamic_cast<Inspector *>(p); }
};

} // namespace

const snort::InspectApi inspect_api = {
    {
        PT_INSPECTOR,
        sizeof(snort::InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        Module::ctor,
        Module::dtor,
    },

    snort::IT_PACKET,
    PROTO_BIT__ALL,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    Inspector::ctor,
    Inspector::dtor,
    nullptr, // ssn
    nullptr  // reset
};

} // namespace trout_netflow
