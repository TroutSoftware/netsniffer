
// Snort includes
#include <framework/decode_data.h>
#include <framework/inspector.h>
#include <framework/module.h>
#include <log/messages.h>

// System includes
#include <cassert>
#include <string>

// Local includes
#include "lioli.h"
#include "log_framework.h"
#include "log_txt.h"

namespace log_txt {
namespace {

static const char *s_name = "log_txt";
static const char *s_help =
    "LioLi tree logger, will output in clear text to specified logger";

static const snort::Parameter module_params[] = {
    {"output", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Set logger output should be sent to"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

// MAIN object of this file
class TxtTreeLogger : public LioLi::LogLioLiTree {
  void log(LioLi::Tree &&tree) override {
    auto &logger = get_stream();
    logger << "vvvvvvvvvvvvvvvvvvvvvvvv\n";
    logger << tree.as_string();
    logger << "^^^^^^^^^^^^^^^^^^^^^^^^\n";
  }

public:
  TxtTreeLogger() : LogLioLiTree(s_name) {}
};

class Module : public snort::Module {
  Module() : snort::Module(s_name, s_help, module_params) {
    // Registers TxtTreeLogger instance
    LioLi::LogDB::register_type<TxtTreeLogger>();
  }

  Usage get_usage() const override {
    return GLOBAL;
  } // TODO(mkr): Figure out what the usage type means

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("output") && val.get_as_string().size() > 0) {
      // Configures the TxtTreeLogger instance
      LioLi::LogDB::get<TxtTreeLogger>(s_name)->set_log_stream_name(
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

} // namespace log_txt
