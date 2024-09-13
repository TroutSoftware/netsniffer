
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
#include "output_to_file.h"

namespace output_to_file {
namespace {

static const char *s_name = "output_to_file";
static const char *s_help = "Maps treelogger output to file";

static const snort::Parameter module_params[] = {
    {"file_name", snort::Parameter::PT_STRING, nullptr, nullptr,
     "File name logs should be written to"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

// MAIN object of this file
class FileLogStream : public LioLi::LogStream {
  std::mutex mutex;
  std::string file_name;
  std::ofstream output_file;
  std::ios_base::openmode open_mode = std::ios_base::out;

  bool ensure_stream() {
    if (!output_file.is_open()) {
      output_file.open(file_name, open_mode);

      if (!output_file.good()) {
        snort::ErrorMessage("ERROR: Could not open output file\n");
      }
    }

    return output_file.good();
  }

  void set_binary_mode() override { open_mode |= std::ios_base::binary; }

  void operator<<(const std::string &&tree) override {
    std::scoped_lock lock(mutex);

    // Output under mutex protection
    if (ensure_stream()) {
      output_file << tree;

      if (!output_file.good()) {
        snort::ErrorMessage("ERROR: Unable to write to output file\n");
      }
    }
  }

public:
  FileLogStream() : LogStream(s_name) {}

  ~FileLogStream() {
    if (output_file.is_open()) {
      output_file.close();
    }
  }

  void set_file_name(std::string name) { file_name = name; }
};

class Module : public snort::Module {
  Module() : snort::Module(s_name, s_help, module_params) {
    LioLi::LogDB::register_type<FileLogStream>();
  }

  Usage get_usage() const override {
    return GLOBAL;
  } // TODO(mkr): Figure out what the usage type means

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("file_name") && val.get_as_string().size() > 0) {
      // Configures the LorthTreeLogger instance
      LioLi::LogDB::get<FileLogStream>(s_name)->set_file_name(val.get_string());
      return true;
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

} // namespace output_to_file
