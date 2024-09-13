
// Snort includes
#include <framework/decode_data.h>
#include <framework/inspector.h>
#include <framework/module.h>
#include <log/messages.h>
#include <managers/inspector_manager.h>

// System includes
#include <cassert>
#include <mutex>
#include <string>

// Local includes
#include "lioli.h"
#include "log_bill.h"
#include "log_framework.h"

namespace log_bill {
namespace {

static const char *s_name = "log_bill";
static const char *s_help =
    "LioLi tree logger, will output in binary lioli (BILL) to specified logger";

static const snort::Parameter module_params[] = {
    {"output", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Set logger output should be sent to"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

// MAIN object of this file
class BillTreeLogger : public LioLi::LogLioLiTree {
  LioLi::LioLi lioli;
  bool first_write = true;
  std::mutex mutex;

  void log(LioLi::Tree &&tree) override {
    std::scoped_lock lock(mutex);
    if (first_write) {
      get_stream().set_binary_mode();
      first_write = false;
    }
    lioli << tree;
    get_stream() << lioli.as_string();
  }

public:
  BillTreeLogger() : LogLioLiTree(s_name) {
    // A binary lioli has a fixed header
    lioli.insert_header();
  }

  ~BillTreeLogger() {
    // If anything was written
    if (!first_write) {
      // A binary lioli must end with a terminator
      lioli.insert_terminator();
      get_stream() << lioli.as_string();
    }
  }
};

class Module : public snort::Module {

  Module() : snort::Module(s_name, s_help, module_params) {
    // Registers BillTreeLogger instance
    LioLi::LogDB::register_type<BillTreeLogger>();
  }

  Usage get_usage() const override {
    return GLOBAL;
  } // TODO(mkr): Figure out what the usage type means

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("output") && val.get_as_string().size() > 0) {
      // Configures the BillTreeLogger instance
      LioLi::LogDB::get<BillTreeLogger>(s_name)->set_log_stream_name(
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

} // namespace log_bill
