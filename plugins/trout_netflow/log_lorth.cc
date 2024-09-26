
// Snort includes
#include <framework/decode_data.h>
#include <framework/inspector.h>
#include <framework/module.h>
#include <log/messages.h>

// System includes
#include <cassert>
#include <memory>
#include <string>

// Local includes
#include "lioli.h"
#include "log_framework.h"
#include "log_lorth.h"

namespace log_lorth {
namespace {

static const char *s_name = "log_lorth";
static const char *s_help =
    "LioLi tree logger, will output in lorth format to specified logger";

static const snort::Parameter module_params[] = {
    {"output", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Set logger output should be sent to"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

// MAIN object of this file
class LorthTreeLogger : public LioLi::LogLioLiTree {
  void log(LioLi::Tree &&tree) override { get_stream() << tree.as_lorth(); }

public:
  LorthTreeLogger() : LogLioLiTree(s_name) {}
};

class Module : public snort::Module {
  Module() : snort::Module(s_name, s_help, module_params) {
    // Registers LorthTreeLogger instance
    LioLi::LogDB::register_type<LorthTreeLogger>();
  }

  Usage get_usage() const override {
    return GLOBAL;
  } // TODO(mkr): Figure out what the usage type means

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("output") && val.get_as_string().size() > 0) {
      // Configures the LorthTreeLogger instance
      LioLi::LogDB::get<LorthTreeLogger>(s_name)->set_log_stream_name(
          val.get_string());
      return true;
    }

    return false;
  }

public:
  static snort::Module *ctor() { return new Module(); }
  static void dtor(snort::Module *p) { delete p; }
};

class Inspector : public snort::Inspector {
  void eval(snort::Packet *) override{};

public:
  static snort::Inspector *ctor(snort::Module *) { return new Inspector(); }
  static void dtor(snort::Inspector *p) { delete p; }
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

    snort::IT_PASSIVE,
    PROTO_BIT__NONE,
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

} // namespace log_lorth
