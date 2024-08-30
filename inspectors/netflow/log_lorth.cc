
// Snort includes
#include <framework/decode_data.h>
#include <framework/inspector.h>
#include <framework/module.h>
#include <log/messages.h>
#include <managers/inspector_manager.h>

// System includes
#include <cassert>
#include <iostream>
#include <mutex>
#include <string>

// Local includes
#include "lioli.h"
#include "log_lioli_stream.h"
#include "log_lioli_tree.h"
#include "log_lorth.h"

namespace log_lorth {
namespace {

static const char *s_name = "log_lorth";
static const char *s_help =
    "LioLi tree logger, will output in lorth format to stdout";

static const snort::Parameter module_params[] = {
    {"output", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Set logger output should be sent to"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

class Module : public snort::Module {
  std::string output_name;

  Module() : snort::Module(s_name, s_help, module_params) {}
  Usage get_usage() const override {
    return GLOBAL;
  } // TODO(mkr): Figure out what the usage type means

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("output") && val.get_as_string().size() > 0) {
      std::cout << "Exp(log_txt): Using Output: " << val.get_as_string()
                << std::endl;
      output_name = val.get_string();
      return true;
    }

    return false;
  }

public:
  std::string &get_output_name() { return output_name; }
  static snort::Module *ctor() { return new Module(); }
  static void dtor(snort::Module *p) { delete p; }
};

class Inspector : public snort::Inspector, public LioLi::LogLioLiTree {
  Module &module;
  LioLi::LogStream *log_stream = nullptr;

  Inspector(Module *module) : module(*module) { assert(module); }

  void eval(snort::Packet *) override{};

  LioLi::LogStream &get_log_stream() {
    if (!log_stream) {
      auto mp = snort::InspectorManager::get_inspector(
          module.get_output_name().c_str(), snort::Module::GLOBAL,
          snort::IT_PASSIVE);
      log_stream = dynamic_cast<LioLi::LogStream *>(mp);

      if (!log_stream) {
        snort::ErrorMessage("ERROR: Alert log_txt doesn't have a valid "
                            "configured output stream\n");

        return LioLi::LogStream::get_null_log_stream();
      }
    }

    return *log_stream;
  }

  void log(LioLi::Tree &&tree) override { get_log_stream() << tree.as_lorth(); }

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
