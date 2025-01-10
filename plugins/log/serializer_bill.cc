
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
#include "serializer_bill.h"

namespace serializer_bill {
namespace {

static const char *s_name = "serializer_bill";
static const char *s_help = "Serializes LioLi trees to BILL format";

static const snort::Parameter module_params[] = {
    {"option_no_root_node", snort::Parameter::PT_BOOL, nullptr, "true",
     "if set will disable generation of root nodes in output"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

// Settings for this module
struct Settings {
  bool option_no_root_node = false;
} settings;

// MAIN object of this file
class Serializer : public LioLi::Serializer {

public:
  Serializer() : LioLi::Serializer(s_name) {}

  ~Serializer() = default;

  class Context : public LioLi::Serializer::Context {
    std::mutex mutex;
    LioLi::LioLi lioli;
    bool first_write = true;
    bool closed = false;

  public:
    std::string serialize(const LioLi::Tree &&tree) override {
      std::scoped_lock lock(mutex);
      if (first_write) {
        if (settings.option_no_root_node) {
          lioli.set_no_root_node();
        }
        lioli.insert_header();
        first_write = false;
      }
      lioli << std::move(tree);

      return lioli.move_binary();
    }

    // Terminate current context, returned byte sequence is any remaining
    // data/end marker of current context.  Context object is invalid after
    // this, except the is_closed() function.
    std::string close() override {
      if (!first_write) {
        // A binary lioli must end with a terminator
        lioli.insert_terminator();
      }
      closed = true;
      return lioli.move_binary();
    }

    // Returns true if context is closed (invalid to call)
    bool is_closed() override { return closed; }
  };

  // Return TRUE if the serialized output is binary, FALSE if it is text based
  bool is_binary() override { return true; };

  std::shared_ptr<LioLi::Serializer::Context> create_context() override {
    return std::make_shared<Context>();
  };
};

class Module : public snort::Module {
  Module() : snort::Module(s_name, s_help, module_params) {
    LioLi::LogDB::register_type<Serializer>();
  }

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("option_no_root_node")) {
      settings.option_no_root_node = val.get_bool();
      return true;
    }

    // fail as we got something we didn't understand
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

} // namespace serializer_bill
