#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes
#include <framework/decode_data.h>
#include <framework/inspector.h>
#include <framework/module.h>

// System includes
#include <cstdint>
#include <iostream>
#include <mutex>
#include <vector>

// Global includes
#include "../includes/lioli.h"
#include "../includes/log_framework.h"

// Local includes
#include "serializer_bin.h"

namespace serializer_bin {
namespace {

static const char *s_name = "serializer_bin";
static const char *s_help =
    "Serializes the body part of LioLi trees into a binary stream";

static const snort::Parameter module_params[] = {
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

const PegInfo s_pegs[] = {
    {CountType::SUM, "tree_count", "Number of trees serialized"},
    {CountType::SUM, "output_bytes", "Total number of bytes generated"},
    {CountType::END, nullptr, nullptr}};

// This must match the s_pegs[] array
// NOTE: we cant use the THREAD_LOCAL pattern here as we have our own threads
std::mutex peg_count_mutex; // Protects the peg counts
struct PegCounts {
  PegCount tree_count = 0;
  PegCount output_bytes = 0;
} s_peg_counts;

// Compile time sanity check of number of entries in s_pegs and s_peg_counts
static_assert(
    (sizeof(s_pegs) / sizeof(PegInfo)) - 1 ==
        sizeof(PegCounts) / sizeof(PegCount),
    "Entries in s_pegs doesn't match number of entries in s_peg_counts");

// Settings for this module
struct Settings {
  bool config_complete = false;
} settings;

// MAIN object of this file
class Serializer : public LioLi::Serializer {

public:
  Serializer(const char *name) : LioLi::Serializer(name) {}

  ~Serializer() = default;

  class Context : public LioLi::Serializer::Context {
    std::mutex mutex;
    bool closed = false;

  public:
    std::string serialize(const LioLi::Tree &&tree) override {
      std::scoped_lock lock(mutex);

      std::string out = tree.as_bin();

      {
        std::scoped_lock lock(peg_count_mutex);
        s_peg_counts.tree_count++;
        s_peg_counts.output_bytes += out.length();
      }

      return out;
    }

    // Terminate current context, returned byte sequence is any remaining
    // data/end marker of current context.  Context object is invalid after
    // this, except the is_closed() function.
    std::string close() override {
      closed = true;

      return "";
    }

    // Returns true if context is closed (invalid to call)
    bool is_closed() override { return closed; }
  };

  // Return TRUE if the serialized output is binary, FALSE if it is text based
  bool is_binary() override { return true; };

  bool is_ready() override { return true; }

  std::shared_ptr<LioLi::Serializer::Context> create_context() override {
    std::shared_ptr<Context> context = std::make_shared<Context>();
    return context;
  };
};

class Module : public snort::Module {
  Module() : snort::Module(s_name, s_help, module_params) {
    LioLi::LogDB::register_type<Serializer>(s_name);
  }

  bool begin(const char *, int, snort::SnortConfig *) override {
    settings.config_complete = false;
    return true;
  }

  bool end(const char *, int, snort::SnortConfig *) override {
    settings.config_complete = true;
    return true;
  }

  bool set(const char *, [[maybe_unused]] snort::Value &val,
           snort::SnortConfig *) override {
    // fail as we got something we didn't understand
    return false;
  }

  Usage get_usage() const override {
    return GLOBAL;
  } // TODO(mkr): Figure out what the usage type means

  const PegInfo *get_pegs() const override { return s_pegs; }

  PegCount *get_counts() const override {
    // We need to return a copy of the peg counts as we don't know when snort
    // are done with them
    static PegCounts static_pegs;

    std::scoped_lock lock(peg_count_mutex);
    static_pegs = s_peg_counts;

    return reinterpret_cast<PegCount *>(&static_pegs);
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

} // namespace serializer_bin
