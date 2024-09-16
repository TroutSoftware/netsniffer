
// Snort includes
#include <framework/decode_data.h>
#include <framework/inspector.h>
#include <framework/module.h>
#include <log/messages.h>
#include <managers/inspector_manager.h>

// System includes
#include <cassert>

// Local includes
#include "log_framework.h"
#include "trout_netflow.h"
#include "trout_netflow_data.h"

// Debug includes

namespace trout_netflow {
namespace {

static const char *s_name = "trout_netflow";
static const char *s_help = "generates netflow data to a lioli logger";

static const snort::Parameter module_params[] = {
    {"logger", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Set logger output should be sent to"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

class Module : public snort::Module {
  Module() : snort::Module(s_name, s_help, module_params) {}

  Usage get_usage() const override { return GLOBAL; }

  std::string logger_name;

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("logger") && val.get_as_string().size() > 0) {
      logger_name = val.get_string();
      return true;
    }

    // fail if we didn't get something valid
    return false;
  }

public:
  std::string &get_logger_name() { return logger_name; }

  static snort::Module *ctor() { return new Module(); }
  static void dtor(snort::Module *p) { delete p; }
};

class Inspector : public snort::Inspector {
  std::string logger_name;
  std::shared_ptr<LioLi::LogLioLiTree> logger;

  Inspector(Module *module) {
    assert(module);

    logger_name = module->get_logger_name();
  }

  std::shared_ptr<LioLi::LogLioLiTree> get_logger() {
    if (!logger) {
      logger = LioLi::LogDB::get<LioLi::LogLioLiTree>(logger_name.c_str());
    }
    return logger;
  }
  void eval(snort::Packet *pkt) override {
    if (pkt && pkt->flow) {
      FlowData *data = FlowData::get_from_flow(pkt->flow, get_logger());
      data->process(pkt);
    } else {
      // TODO: log pkt without flow
    }
  };

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

    snort::IT_PROBE,
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
