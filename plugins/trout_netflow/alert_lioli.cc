
// Snort includes
#include <events/event.h>
#include <framework/module.h>
#include <log/messages.h>
#include <protocols/packet.h>

// System includes
#include <cassert>
#include <iostream>

// Local includes
#include "alert_lioli.h"
#include "flow_data.h"
#include "lioli_tree_generator.h"
#include "log_framework.h"

namespace alert_lioli {
namespace {

static const char *s_name = "alert_lioli";
static const char *s_help =
    "lioli logger, will output through a log module compatible with lioli";

static const snort::Parameter module_params[] = {
    {"logger", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Set logger output should be sent to"},
    {"timestamp", snort::Parameter::PT_BOOL, nullptr, "true",
     "Set to false if timestamps should not be generated"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

class Module : public snort::Module {

  Module() : snort::Module(s_name, s_help, module_params) {}

  std::string logger_name;
  bool log_timestamp;

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("logger") && val.get_as_string().size() > 0) {
      logger_name = val.get_string();
      return true;
    } else if (val.is("timestamp")) {
      log_timestamp = val.get_bool();
    } else {
      // fail if we didn't get something valid
      return false;
    }

    return true;
  }

  Usage get_usage() const override { return GLOBAL; }

public:
  std::string &get_logger_name() { return logger_name; }
  bool get_log_timestamp() { return log_timestamp; }

  static snort::Module *ctor() { return new Module(); }
  static void dtor(snort::Module *p) { delete p; }
};

class Logger : public snort::Logger {
  Module &module;
  bool log_timestamp = true;
  std::shared_ptr<LioLi::LogLioLiTree> logger;

  LioLi::LogLioLiTree &get_logger() {
    if (!logger) {
      logger = LioLi::LogDB::get<LioLi::LogLioLiTree>(
          module.get_logger_name().c_str());
    }

    return *logger.get();
  }

private:
  Logger(Module *module)
      : module(*module), log_timestamp(module->get_log_timestamp()) {
    assert(module);
  }

  void alert(snort::Packet *pkt, const char *msg, const Event &) override {
    get_logger().log(std::move(gen_tree("ALERT", pkt, msg)));
  }

  void log(snort::Packet *pkt, const char *msg, Event *) override {
    get_logger().log(std::move(gen_tree("log", pkt, msg)));
  }

  LioLi::Tree gen_tree(const char *type, snort::Packet *pkt, const char *msg) {
    assert(type && pkt && msg);

    LioLi::Tree root("$");

    if (log_timestamp) {
      root << LioLi::TreeGenerators::timestamp("AlertTime");
    }

    root << (LioLi::Tree(type) << msg);

    // format_IP_MAC handles a null flow
    root << (LioLi::Tree("principal")
             << LioLi::TreeGenerators::format_IP_MAC(pkt, pkt->flow, true));

    root << (LioLi::Tree("endpoint")
             << LioLi::TreeGenerators::format_IP_MAC(pkt, pkt->flow, false));

    if (pkt->flow && pkt->flow->service) {
      root << (LioLi::Tree("protocol") << pkt->flow->service);
    }

    if (pkt->flow) {
      root << *NetFlow::FlowData::get_from_flow(pkt->flow);
    }

    return root;
  }

public:
  static snort::Logger *ctor(snort::Module *module) {
    return new Logger(dynamic_cast<Module *>(module));
  }

  static void dtor(snort::Logger *p) { delete dynamic_cast<Logger *>(p); }
};

} // namespace

typedef Logger *(*LogNewFunc)(class Module *);
typedef void (*LogDelFunc)(Logger *);

const snort::LogApi log_api = {
    {
        PT_LOGGER,
        sizeof(snort::LogApi),
        LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        Module::ctor,
        Module::dtor,
    },
    OUTPUT_TYPE_FLAG__ALERT,
    Logger::ctor,
    Logger::dtor,
};

} // namespace alert_lioli
