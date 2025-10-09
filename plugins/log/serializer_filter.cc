// Snort includes
#include <framework/decode_data.h>
#include <framework/inspector.h>
#include <framework/module.h>

// System includes
#include <memory>

// Local includes
#include "lioli.h"
#include "log_framework.h"
#include "serializer_filter.h"

// Debug includes
#include <iostream>

namespace serializer_filter {
namespace {

const char *s_name = "serializer_filter";
const char *s_help = "tweaks the output from a different filter";

const snort::Parameter module_params[] = {
    {"alias", snort::Parameter::PT_STRING, nullptr, nullptr,
     "The alias name for the filter with specific config"},
    {"serializer", snort::Parameter::PT_STRING, nullptr, nullptr,
     "The serializer this filter should modify "},
    {"stream_prefix", snort::Parameter::PT_STRING, nullptr, nullptr,
     "string that each stream should be prefixed with (remember strings are in "
     "lua format, e.g. add \0 to the end if it should be zero termianted \"my "
     "string\\0\")"},
    {"stream_postfix", snort::Parameter::PT_STRING, nullptr, nullptr,
     "string that each stream should be postfixed with"},
    {"tree_delimiter", snort::Parameter::PT_STRING, nullptr, nullptr,
     "string that will be inserted between any two log entries"},

    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

const PegInfo s_pegs[] = {
    {CountType::SUM, "log_count", "Count of logs we processed"},
    {CountType::SUM, "stream_count", "Number of streams"},
    {CountType::SUM, "bytes_in",
     "How many bytes the serializer returned to us"},
    {CountType::SUM, "bytes_out", "How many bytes we send out"},
    {CountType::END, nullptr, nullptr}};

// This must match the s_pegs[] array
// NOTE: we cant use the THREAD_LOCAL pattern here as we have our own threads
std::mutex peg_count_mutex; // Protects the peg counts
struct PegCounts {
  PegCount log_count = 0;
  PegCount stream_count = 0;
  PegCount bytes_in = 0;
  PegCount bytes_out = 0;
} s_peg_counts;

// Compile time sanity check of number of entries in s_pegs and s_peg_counts
static_assert(
    (sizeof(s_pegs) / sizeof(PegInfo)) - 1 ==
        sizeof(PegCounts) / sizeof(PegCount),
    "Entries in s_pegs doesn't match number of entries in s_peg_counts");

class Serializer : public LioLi::Serializer {
  struct Settings {
    std::shared_ptr<LioLi::Serializer>
        serializer; // Don't access directly, use get_serializer()
  public:
    std::string prefix;
    std::string postfix;
    std::string delimiter;
    std::string serializer_name;

    LioLi::Serializer &get_serializer() {
      // Only do a lookup if needed
      if (!serializer || serializer == get_null_obj()) {
        serializer = LioLi::LogDB::get<LioLi::Serializer>(serializer_name);
      }

      return *serializer;
    }
  };

  std::shared_ptr<Settings> settings = std::make_shared<Settings>();

public:
  Serializer(const char *my_name) : LioLi::Serializer(my_name) {}

  // There might be multiple serialization contexts in use at any given time or
  // sequentially, if serialization is in anyway state full, then we need  a
  // different object for each
  class Context : public LioLi::Serializer::Context {
    std::shared_ptr<Settings> settings;
    std::shared_ptr<LioLi::Serializer::Context> context;
    bool first_iteration = true;

  public:
    Context(std::shared_ptr<Settings> settings)
        : settings(settings),
          context(settings->get_serializer().create_context()) {}

    // Function that does the serialization, input is a LioLi tree and output is
    // a byte sequence, including any needed headers at the beginning, note
    // might return an empty object
    std::string serialize(const LioLi::Tree &&tree) override {
      if (first_iteration) {
        first_iteration = false;
        return settings->prefix + context->serialize(std::move(tree));
      } else if (settings->delimiter.size()) {
        return settings->delimiter + context->serialize(std::move(tree));
      }
      return context->serialize(std::move(tree));
    }

    // Terminate current context, returned byte sequence is any remaining
    // data/end marker of current context.  Context object is invalid after
    // this, except the is_closed() function.
    std::string close() override {
      return context->close() + settings->postfix;
    }

    // Returns true if context is closed (invalid to call)
    bool is_closed() override { return context->is_closed(); }
  };

  // Return TRUE if the serialized output is binary, FALSE if it is text based
  bool is_binary() override { return settings->get_serializer().is_binary(); }

  std::shared_ptr<LioLi::Serializer::Context> create_context() override {
    return std::make_shared<Context>(settings);
  };

  void set_prefix(std::string &&prefix) {
    settings->prefix = std::move(prefix);
  }
  void set_postfix(std::string &&postfix) {
    settings->postfix = std::move(postfix);
  }
  void set_delimiter(std::string &&delimiter) {
    settings->delimiter = std::move(delimiter);
  }
  void set_serializer(std::string &&serializer_name) {
    settings->serializer_name = std::move(serializer_name);
  }
};

class Module : public snort::Module {
  Module() : snort::Module(s_name, s_help, module_params) {}

  ~Module() {}

  struct ConfigColector {
    std::string name;
    std::string prefix;
    std::string postfix;
    std::string delimiter;
    std::string serializer;
  };

  std::stack<ConfigColector> config_stack;

  bool begin(const char *, int, snort::SnortConfig *) override {
    // Make new element
    config_stack.emplace();
    return true;
  }

  bool end(const char *, int, snort::SnortConfig *) override {
    assert(!config_stack.empty());

    // Check validity
    if (config_stack.top().name.empty()) {
      if (config_stack.size() > 1) {
        snort::ErrorMessage("ERROR: No alias given for entry\n");
        config_stack.pop();
        return false;
      }

      config_stack.top().name = s_name;
    }

    if (config_stack.top().serializer.empty()) {
      snort::ErrorMessage("ERROR: No serializer given for entry\n");
      std::cout << "MKRTEST: name= " << config_stack.top().name << std::endl;
      config_stack.pop();
      return false;
    }

    // Create entry in DB
    if (!LioLi::LogDB::register_type<Serializer>(
            config_stack.top().name.c_str())) {
      snort::ErrorMessage("ERROR: Found duplicate name/alias '%s'\n",
                          config_stack.top().name.c_str());
      config_stack.pop();
      return false;
    }

    auto serializer =
        LioLi::LogDB::get<Serializer>(config_stack.top().name.c_str());

    if (!serializer) {
      snort::ErrorMessage("ERROR: Unable to initialize filter serializer\n");
      config_stack.pop();
      return false;
    }

    // Initialize specific serializer
    serializer->set_prefix(std::move(config_stack.top().prefix));
    serializer->set_postfix(std::move(config_stack.top().postfix));
    serializer->set_delimiter(std::move(config_stack.top().delimiter));
    serializer->set_serializer(std::move(config_stack.top().serializer));

    config_stack.pop();
    return true;
  }

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    assert(!config_stack.empty());

    if (val.is("alias")) {
      // TODO: Check for spaces in the name
      std::string alias = val.get_as_string();

      if (alias.empty()) {
        snort::ErrorMessage("ERROR: Alias specified with empty name\n");
        return false;
      }

      config_stack.top().name = alias;

    } else if (val.is("stream_prefix")) {
      config_stack.top().prefix = val.get_unquoted_string();
    } else if (val.is("stream_postfix")) {
      config_stack.top().postfix = val.get_unquoted_string();
    } else if (val.is("tree_delimiter")) {
      config_stack.top().delimiter = val.get_unquoted_string();
    } else if (val.is("serializer")) {
      std::string serializer = val.get_as_string();

      if (serializer.empty()) {
        snort::ErrorMessage("ERROR: empty name given for serializer\n");
        return false;
      }

      config_stack.top().serializer = serializer;
    } else {
      snort::ErrorMessage("ERROR: Parameter '%s' is not implemented\n",
                          val.get_name());
      return false;
    }

    return true;
  }

  Usage get_usage() const override {
    return GLOBAL;
  } // TODO(mkr): Figure out what the usage type means

  const PegInfo *get_pegs() const override { return s_pegs; }

  PegCount *get_counts() const override {
    // TODO: This will mess when snort tries to clear the pegs, find a solution
    // that lets this work in a multithreaded environment
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

} // namespace serializer_filter
