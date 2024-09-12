
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
#include "output_to.h"
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

class Module : public snort::Module {
  Module() : snort::Module(s_name, s_help, module_params) {}

  Usage get_usage() const override {
    return GLOBAL;
  } // TODO(mkr): Figure out what the usage type means

  std::string pipe_name;

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("pipe_name") && val.get_as_string().size() > 0) {
      pipe_name = val.get_string();

      return true;
    } else if (val.is("pipe_env")) {
      std::string env_name = val.get_as_string();
      const char *name = std::getenv(env_name.c_str());

      if (name && *name) {
        pipe_name = name;

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

  std::string &get_pipe_name() { return pipe_name; }
};

class Inspector : public snort::Inspector, public LioLi::LogStream {
  std::string output_name;
  std::ofstream output_pipe;
  std::ios_base::openmode open_mode = std::ios_base::out;

  Inspector(Module *module) : LogStream(s_name) {
    assert(module);
    output_name = module->get_pipe_name();
  }

public: // shared_ptr needs access to the destructor
  ~Inspector() {
    if (output_pipe.is_open()) {
      output_pipe.close();
    }
  }

private:
  bool ensure_stream_is_good() {
    if (output_pipe.good() && output_pipe.is_open()) {
      return true;
    }

    if (!output_pipe.is_open()) {
      output_pipe.open(output_name, open_mode);
    }

    if (!output_pipe.good()) {
      snort::ErrorMessage("ERROR: Could not open output pipe\n");
      return false;
    }

    return true;
  }

  void eval(snort::Packet *) override {};

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

  std::shared_ptr<Inspector>
      snort_ptr; // Used to keep object alive while snort uses it
  friend std::shared_ptr<Inspector>;

public:
  static snort::Inspector *ctor(snort::Module *module) {
    assert(module);
    // We use std::shared_ptr<>(new...) instead of make_shared to keep the
    // constructor private
    Inspector *tmp = new Inspector(dynamic_cast<Module *>(module));
    std::shared_ptr<Inspector> new_inspector = std::shared_ptr<Inspector>(tmp);
    tmp->snort_ptr.swap(new_inspector);
    return tmp;
  }
  static void dtor(snort::Inspector *p) {
    Inspector *forget = dynamic_cast<Inspector *>(p);
    assert(forget->snort_ptr); // The pointer snort gave us was not of the
                               // correct type

    // We don't want to call reset on a member while we destroy it
    [[maybe_unused]] std::shared_ptr<Inspector> tmp(
        std::move(forget->snort_ptr));
  }
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
