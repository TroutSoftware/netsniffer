
// Snort includes
#include <framework/decode_data.h>
#include <framework/inspector.h>
#include <framework/module.h>

// System includes
#include <iostream>
#include <mutex>

// Local includes
#include "lioli.h"
#include "log_lioli_tree.h"
#include "log_txt.h"

namespace log_txt {
namespace {

static const char *s_name = "log_txt";
static const char *s_help =
    "LioLi tree logger, will output in clear text to stdout";

static const snort::Parameter module_params[] = {
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

class Module : public snort::Module {
  Module() : snort::Module(s_name, s_help, module_params) {}
  Usage get_usage() const override {
    return GLOBAL;
  } // TODO(mkr): Figure out what the usage type means

public:
  static snort::Module *ctor() { return new Module(); }
  static void dtor(snort::Module *p) { delete p; }
};

class Inspector : public snort::Inspector, public LioLi::LogLioLiTree {
private:
  void eval(snort::Packet *) override{};

  void log(LioLi::Tree &&tree) override {
    static std::mutex mutex;
    std::scoped_lock lock(mutex);

    // Output under mutex protection
    std::cout << tree.as_string();
  }

public:
  static snort::Inspector *ctor(snort::Module *) { return new Inspector(); }
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
