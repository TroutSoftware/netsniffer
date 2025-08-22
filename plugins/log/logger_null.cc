
// Snort includes
#include <framework/decode_data.h>
#include <framework/inspector.h>
#include <framework/module.h>

// System includes
#include <iostream>
#include <mutex>

// Local includes
#include "lioli.h"
#include "log_framework.h"
#include "logger_null.h"

// Debug includes

namespace logger_null {
namespace {

static const char *s_name = "logger_null";
static const char *s_help = "Null logger, anything sent to it will disappear";

static const snort::Parameter module_params[] = {
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

// MAIN object of this file
class Logger : public LioLi::Logger {

public:
  Logger(const char *name) : LioLi::Logger(name) {}

  ~Logger() {}

  bool had_data_loss(bool) override { return false; }

  void operator<<(const LioLi::Tree &&) override {}
};

class Module : public snort::Module {
  Module() : snort::Module(s_name, s_help, module_params) {
    LioLi::LogDB::register_type<Logger>(s_name);
  }

  bool set(const char *, snort::Value &, snort::SnortConfig *) override {
    // fail if we didn't get something valid
    return false;
  }

  Usage get_usage() const override {
    return GLOBAL;
  } // TODO(mkr): Figure out what the usage type means

public:
  static snort::Module *ctor() { return new Module(); }
  static void dtor(snort::Module *p) { delete p; }
};

class Inspector : public snort::Inspector {
  void eval(snort::Packet *) override {};

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

} // namespace logger_null
