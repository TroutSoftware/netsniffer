
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
#include "log_framework.h"
#include "output_to_pipe.h"

namespace output_to_pipe {
namespace {

static const char *s_name = "output_to_pipe";
static const char *s_help = "Maps treelogger output to a pipe";

static const snort::Parameter module_params[] = {
    {"pipe_name", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Pipe name logs should be written to"},
    {"pipe_env", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Pipe name will be read from environment variable"},

    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

// MAIN object of this file
class PipeLogStream : public LioLi::LogStream {
  std::string pipe_name;
  std::ofstream output_pipe;
  std::ios_base::openmode open_mode = std::ios_base::out;

  bool ensure_stream_is_good() {
    if (output_pipe.good() && output_pipe.is_open()) {
      return true;
    }

    if (!output_pipe.is_open()) {
      output_pipe.open(pipe_name, open_mode);
    }

    if (!output_pipe.good()) {
      snort::ErrorMessage("ERROR: Could not open output pipe\n");
      return false;
    }

    return true;
  }

  void set_binary_mode() override { open_mode |= std::ios_base::binary; }

  void operator<<(const std::string &&tree) override {
    static std::mutex mutex;
    std::scoped_lock lock(mutex);

    // Output under mutex protection
    if (ensure_stream_is_good()) {
      output_pipe << tree;

      if (!output_pipe.good()) {
        snort::ErrorMessage("ERROR: Unable to write to output pipe\n");
      }
    }
  }

public:
  PipeLogStream() : LogStream(s_name) {}

  ~PipeLogStream() {
    if (output_pipe.is_open()) {
      output_pipe.close();
    }
  }

  void set_pipe_name(std::string name) { pipe_name = name; }
};

class Module : public snort::Module {
  Module() : snort::Module(s_name, s_help, module_params) {
    LioLi::LogDB::register_type<PipeLogStream>();
  }

  Usage get_usage() const override {
    return GLOBAL;
  } // TODO(mkr): Figure out what the usage type means

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("pipe_name") && val.get_as_string().size() > 0) {

      LioLi::LogDB::get<PipeLogStream>(s_name)->set_pipe_name(val.get_string());

      return true;
    } else if (val.is("pipe_env")) {
      std::string env_name = val.get_as_string();
      const char *name = std::getenv(env_name.c_str());

      if (name && *name) {
        LioLi::LogDB::get<PipeLogStream>(s_name)->set_pipe_name(name);

        return true;
      }

      snort::ErrorMessage(
          "ERROR: Could not read log pipe name from environment\n");
    }

    // fail if we didn't get something valid
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

} // namespace output_to_pipe
