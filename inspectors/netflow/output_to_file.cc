
// Snort includes
#include <framework/decode_data.h>
#include <framework/inspector.h>
#include <framework/module.h>
#include <log/messages.h>

// System includes
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>

// Local includes
#include "lioli.h"
#include "log_lioli_stream.h"
#include "output_to_file.h"

namespace output_to_file {
namespace {

static const char *s_name = "output_to_file";
static const char *s_help = "Maps treelogger output to file";

static const snort::Parameter module_params[] = {
    {"file_name", snort::Parameter::PT_STRING, nullptr, nullptr,
   "File name logs should be written to"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

class Module : public snort::Module {
  Module() : snort::Module(s_name, s_help, module_params) {}

  Usage get_usage() const override {
    return GLOBAL;
  } // TODO(mkr): Figure out what the usage type means

  std::string file_name;

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("file_name") && val.get_as_string().size() > 0) {
      file_name = val.get_string();
      return true;
    }

    // fail if we didn't get something valid
    return false;
  }


public:
  static snort::Module *ctor() { return new Module(); }
  static void dtor(snort::Module *p) { delete p; }

  std::string& get_file_name() {return file_name;}
};

class Inspector : public snort::Inspector, public LioLi::LogStream {
  Module &module;

  std::ofstream output_file;

  Inspector(Module &module) : module(module) {
    output_file.open(module.get_file_name());

    if(!output_file.good()) {
      snort::ErrorMessage("ERROR: Could not open output file\n");
    }
  }

  ~Inspector() {
    if (output_file.is_open()) {
      output_file.close();
    }
  }

  void eval(snort::Packet *) override {};

  void set_binary_mode() override {
    // TODO: Make file output in binary mode
  }

  void operator<<(const std::string &tree) override {
    if(!output_file.good()) {
      snort::ErrorMessage("ERROR: Could not write log to file\n");
      return;
    }

    static std::mutex mutex;
    std::scoped_lock lock(mutex);

    // Output under mutex protection
    output_file << tree;
  }

public:
  static snort::Inspector *ctor(snort::Module *module) {
    assert(module);
    return new Inspector(*dynamic_cast<Module*>(module));
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

} // namespace log_to_file
