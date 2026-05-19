#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes
#include <framework/decode_data.h>
#include <framework/inspector.h>
#include <framework/module.h>
#include <log/messages.h>

// System includes
#include <fstream>
#include <iostream>
#include <mutex>

// Global includes
#include "../includes/lioli.h"
#include "../includes/log_framework.h"

// Local includes
#include "logger_file.h"

// Debug includes

namespace logger_file {
namespace {

static const char *s_name = "logger_file";
static const char *s_help =
    "Outputs LioLi trees stdout, it only supports text output";

static const snort::Parameter module_params[] = {
    {"file_name", snort::Parameter::PT_STRING, nullptr, nullptr,
     "File name logs should be written to"},
    {"file_env", snort::Parameter::PT_STRING, nullptr, nullptr,
     "File name will be read from environment variable"},
    {"serializer", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Serializer to use for generating output"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

struct Settings {
  std::string serializer_name;
  std::string file_name;
};

const PegInfo s_pegs[] = {
    {CountType::SUM, "logs_in", "Count of logs we were asked to write"},
    {CountType::SUM, "logs_out", "Count of logs we have written to the file"},
    {CountType::SUM, "write_errors", "Count of write errors detected"},
    {CountType::END, nullptr, nullptr}};

// This must match the s_pegs[] array
THREAD_LOCAL struct PegCounts {
  PegCount logs_in = 0;
  PegCount logs_out = 0;
  PegCount write_errors = 0;
} s_peg_counts;

// Compile time sanity check of number of entries in s_pegs and s_peg_counts
static_assert(
    (sizeof(s_pegs) / sizeof(PegInfo)) - 1 ==
        sizeof(PegCounts) / sizeof(PegCount),
    "Entries in s_pegs doesn't match number of entries in s_peg_counts");

// MAIN object of this file
class Logger : public LioLi::Logger {
  std::mutex mutex; // Protects members

  const std::shared_ptr<Settings> settings;

  std::shared_ptr<LioLi::Serializer::Context> context;
  std::ofstream ofile;

  LioLi::Serializer::Context &get_context() {
    if (!context) {
      auto serializer =
          LioLi::LogDB::get<LioLi::Serializer>(settings->serializer_name);

      context = serializer->create_context();
    }

    return *context.get();
  }

  std::ofstream &get_ofile() {
    if (!ofile.is_open()) {
      std::ios_base::openmode open_mode = std::ios_base::out;

      auto serializer =
          LioLi::LogDB::get<LioLi::Serializer>(settings->serializer_name);

      if (serializer->is_binary()) {
        open_mode |= std::ios_base::binary;
      }

      ofile.open(settings->file_name, open_mode);

      if (!ofile.good()) {
        snort::ErrorMessage("ERROR: Could not open output file >%s<\n",
                            settings->file_name.c_str());
      }
    }
    return ofile;
  }

public:
  Logger(const char *name, std::shared_ptr<Settings> &settings)
      : LioLi::Logger(name), settings(settings) {
    assert(settings); // Settings need to point to something valid
  }

  ~Logger() {
    if (ofile.good() && ofile.is_open()) {
      if (context) {
        ofile << context->close();
      }

      ofile.close();
    }
  }

  bool is_ready() override {
    return get_ofile().good() &&
           LioLi::LogDB::get<LioLi::Serializer>(settings->serializer_name)
               ->is_ready();
  }

  void operator<<(const LioLi::Tree &&tree) override {
    std::scoped_lock lock(mutex);
    s_peg_counts.logs_in++;

    auto &ofile = get_ofile();
    ofile << get_context().serialize(std::move(tree));

    if (!ofile.good()) {
      data_loss_tracker.rearm();
      // data_loss = true;
      s_peg_counts.write_errors++;
    } else {
      s_peg_counts.logs_out++;
      data_loss_tracker.trigger();
    }
  }
};

class Module : public snort::Module {
  Module() : snort::Module(s_name, s_help, module_params) {}

  std::shared_ptr<Settings> settings;

  bool begin(const char *, int, snort::SnortConfig *) override {
    if (settings) {
      // We can't handle multiple settings
      snort::ErrorMessage(
          "ERROR: %s can't handle reconfiguration/multiple configs\n", s_name);
      return false;
    }
    settings = std::make_shared<Settings>();
    return true;
  }

  bool end(const char *, int, snort::SnortConfig *) override {
    assert(settings); // We didn't have a sucesful begin

    if (settings->file_name.empty()) {
      snort::ErrorMessage("ERROR: no file_name specified for %s\n", s_name);
      return false;
    }

    if (settings->serializer_name.empty()) {
      snort::ErrorMessage("ERROR: serializer not specified for %s\n", s_name);
      return false;
    }

    // Only register if we are correctly set up
    LioLi::LogDB::register_type<Logger>(s_name, settings);

    return true;
  }

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {

    assert(settings); // We didn't have a begin

    if (val.is("serializer") && val.get_as_string().size() > 0) {
      settings->serializer_name = val.get_string();

      return true;
    } else if (val.is("file_name") && val.get_as_string().size() > 0) {
      if (!settings->file_name.empty()) {
        snort::ErrorMessage("ERROR: You can only set name/env once in %s\n",
                            s_name);
        return false;
      }

      settings->file_name = val.get_string();

      return true;
    } else if (val.is("file_env")) {
      std::string env_name = val.get_as_string();
      const char *name = std::getenv(env_name.c_str());

      if (name && *name) {
        if (!settings->file_name.empty()) {
          snort::ErrorMessage("ERROR: You can only set name/env once in %s\n",
                              s_name);
          return false;
        }

        settings->file_name = name;

        return true;
      }

      snort::ErrorMessage(
          "ERROR: Could not read log file name from environment: %s in %s\n",
          env_name.c_str(), s_name);
    }

    // fail if we didn't get something valid
    return false;
  }

  Usage get_usage() const override {
    return GLOBAL;
  } // TODO(mkr): Figure out what the usage type means

  const PegInfo *get_pegs() const override { return s_pegs; }

  PegCount *get_counts() const override {
    return reinterpret_cast<PegCount *>(&s_peg_counts);
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

} // namespace logger_file
