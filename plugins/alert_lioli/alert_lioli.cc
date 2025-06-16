
// Snort includes
#include <events/event.h>
#include <framework/module.h>
#include <log/messages.h>
#include <protocols/packet.h>

// System includes
#include <cassert>
#include <iostream>

// Global includes
#include <lioli_path.h>
#include <lioli_tree_generator.h>
#include <log_framework.h>

// Local includes
#include "alert_lioli.h"
#include "common.h"

// Debug includes

namespace alert_lioli {
namespace {

static const char *s_name = "alert_lioli";
static const char *s_help =
    "lioli logger, will output through a log module compatible with lioli";

static const snort::Parameter module_params[] = {
    {"logger", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Set logger output should be sent to"},
    {"testmode", snort::Parameter::PT_BOOL, nullptr, "false",
     "if set to true it will give consistent output, like using fixed "
     "timestamps"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

const PegInfo s_pegs[] = {
    {CountType::SUM, "alerts_generated", "Number of alerts generated"},
    {CountType::SUM, "logs_generated", "Number of logs generated"},
    {CountType::END, nullptr, nullptr}};

// This must match the s_pegs[] array
THREAD_LOCAL struct PegCounts {
  PegCount alerts_generated = 0;
  PegCount logs_generated = 0;
} s_peg_counts;

// Compile time sanity check of number of entries in s_pegs and s_peg_counts
static_assert(
    (sizeof(s_pegs) / sizeof(PegInfo)) - 1 ==
        sizeof(PegCounts) / sizeof(PegCount),
    "Entries in s_pegs doesn't match number of entries in s_peg_counts");

class Module : public snort::Module {

  Module() : snort::Module(s_name, s_help, module_params) {}

  std::string logger_name;
  bool testmode = false;

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("logger") && val.get_as_string().size() > 0) {
      logger_name = val.get_string();
    } else if (val.is("testmode")) {
      testmode = val.get_bool();
    } else {
      // fail if we didn't get something valid
      return false;
    }

    return true;
  }

  Usage get_usage() const override { return GLOBAL; }

  const PegInfo *get_pegs() const override { return s_pegs; }

  PegCount *get_counts() const override {
    return reinterpret_cast<PegCount *>(&s_peg_counts);
  }

public:
  std::string &get_logger_name() { return logger_name; }
  bool get_testmode() { return testmode; }

  static snort::Module *ctor() { return new Module(); }
  static void dtor(snort::Module *p) { delete p; }
};

class Logger : public snort::Logger {
  Module &module;
  bool testmode = true;

  std::shared_ptr<LioLi::Logger> logger;

  LioLi::Logger &get_logger() {
    if (!logger) {
      logger =
          LioLi::LogDB::get<LioLi::Logger>(module.get_logger_name().c_str());
    }
    return *logger.get();
  }

private:
  Logger(Module *module) : module(*module), testmode(module->get_testmode()) {
    assert(module);
  }

  void alert(snort::Packet *pkt, const char *msg, const Event &e) override {
    s_peg_counts.alerts_generated++;
    get_logger() << std::move(gen_tree("alert", pkt, msg, &e));
  }

  void log(snort::Packet *pkt, const char *msg, Event *e) override {
    s_peg_counts.logs_generated++;
    get_logger() << std::move(gen_tree("log", pkt, msg, e));
  }

  LioLi::Tree gen_tree(const char *type, snort::Packet *pkt, const char *msg,
                       const Event *e) {
    assert(type && pkt && msg);

    LioLi::Path root("$");

    root << LioLi::TreeGenerators::timestamp("timestamp", testmode);

    if (e) {
      root << (LioLi::Tree("sid") << e->get_sid());
      root << (LioLi::Tree("gid") << e->get_gid());
      root << (LioLi::Tree("rev") << e->get_rev());
    }

    root << (LioLi::Tree(type) << msg);

    // format_IP_MAC handles a null flow
    root << (LioLi::Path("$.principal")
             << LioLi::TreeGenerators::format_IP_MAC(pkt, pkt->flow, true));

    root << (LioLi::Path("$.endpoint")
             << LioLi::TreeGenerators::format_IP_MAC(pkt, pkt->flow, false));

    if (pkt->flow && pkt->flow->service) {
      root << (LioLi::Tree("protocol") << pkt->flow->service);
    }

    if (pkt->flow) {
      root << *FlowData::get_from_flow(pkt->flow);
    }

    return root.to_tree();
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
