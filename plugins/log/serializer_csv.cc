
// Snort includes
#include <framework/decode_data.h>
#include <framework/inspector.h>
#include <framework/module.h>

// System includes
#include <format>
#include <iostream>
#include <mutex>

// Local includes
#include "lioli.h"
#include "log_framework.h"
#include "serializer_csv.h"

namespace serializer_csv {
namespace {

static const char *s_name = "serializer_csv";
static const char *s_help = "Serializes parts of LioLi trees to csv format";

/*
serializer_csv = {
  item_seperator = " ",
  items= { { lookup = "$.#Chunks.chunk.first_from",
             map = { { if_input = "",       then_output = "-" },
                     { if_input = "client", then_output = "S" },
                     { if_input = "server", then_output = "C" },
                     { default_output = "O" } } },
           { seperator = " " },
           { lookup = "$.protocol",
             map = { { if_input = "",    then_output = "-" },
                     { if_input = "TCP", then_output = "T" },
                     { if_input = "UDP", then_output = "U" },
                     { default_output = "O" } } },
           { seperator = " " },
           { lookup = "$.port", },
           { seperator = " " },
           { lookup_regex = "\\$\\.\\#Chunks\\.chunk\\.(client|server)\\.data",
             format_as_hex = true,
             pad = { padding = "0",
                     length = 2048 }
             truncate_input_after = 1024,
  }
}

*/

static const snort::Parameter map_params[] = {
    {"if_input", snort::Parameter::PT_STRING, nullptr, nullptr,
     "(NOT IMPLEMENTED) key of entry"},
    {"then_output", snort::Parameter::PT_STRING, nullptr, nullptr,
     "(NOT IMPLEMENTED) value of entry"},
    {"default_output", snort::Parameter::PT_STRING, nullptr, nullptr,
     "(NOT IMPLEMENTED) default value of map"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

static const snort::Parameter pad_params[] = {
    {"padding", snort::Parameter::PT_STRING, nullptr, nullptr,
     "(NOT IMPLEMENTED) padding string/char"},
    {"length", snort::Parameter::PT_INT, "1:max53", nullptr,
     "(NOT IMPLEMENTED) length that should be padded to"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

static const snort::Parameter item_params[] = {
    {"lookup", snort::Parameter::PT_STRING, nullptr, nullptr,
     "(NOT IMPLEMENTED) key of entry"},
    {"lookup_regex", snort::Parameter::PT_STRING, nullptr, nullptr,
     "(NOT IMPLEMENTED) key of entry as regex, all values will be concatenated "
     "as input"},
    {"truncate_input_after", snort::Parameter::PT_INT, "1:max53", nullptr,
     "(NOT IMPLEMENTED) max size of input value that will be considered"},
    {"format_as_hex", snort::Parameter::PT_BOOL, nullptr, "false",
     "(NOT IMPLEMENTED) set to true to get all input converted to hex"},
    {"map", snort::Parameter::PT_LIST, map_params, nullptr,
     "(NOT IMPLEMENTED) map to translate input to output"},
    {"pad_output", snort::Parameter::PT_TABLE, pad_params, nullptr,
     "(NOT IMPLEMENTED) padding options of output"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

static const snort::Parameter module_params[] = {
    {"item_separator", snort::Parameter::PT_STRING, nullptr, ", ",
     "string inserted between each item"},
    {"items", snort::Parameter::PT_LIST, item_params, nullptr,
     "(NOT IMPLEMENTED) list of items that should be added"},
    {"if_item_blank_then_output", snort::Parameter::PT_STRING, nullptr, "-",
     "string to output if item is missing or empty"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

// Settings for this module
struct Settings {
  std::string separator;
  std::string blank_replace;
} settings;

// MAIN object of this file
class Serializer : public LioLi::Serializer {

public:
  Serializer() : LioLi::Serializer(s_name) {}

  ~Serializer() = default;

  class Context : public LioLi::Serializer::Context {
    bool closed = false;

  public:
    std::string serialize(const LioLi::Tree &&tree) override {

      // Input is where data is from, output is where it is going to
      std::map<std::string, std::string> direction_map;
      direction_map[""] = settings.blank_replace;
      direction_map["client"] = "S";
      direction_map["server"] = "C";
      std::string direction = tree.lookup("$.#Chunks.chunk.first_from");
      std::string output =
          (direction_map.contains(direction) ? direction_map[direction] : "O") +
          settings.separator;

      std::map<std::string, std::string> protocol_map;
      protocol_map[""] = settings.blank_replace;
      protocol_map["TCP"] = "T";
      protocol_map["UDP"] = "U";
      std::string protocol = tree.lookup("$.protocol");
      output +=
          (protocol_map.contains(protocol) ? protocol_map[protocol] : "O") +
          settings.separator;

      std::string port = tree.lookup("$.port");
      output += (port.length() > 0 ? port : settings.blank_replace) +
                settings.separator;

      std::string data;
      tree.regex_lookup("\\$\\.\\#Chunks\\.chunk\\.(client|server)\\.data",
                        [&data](std::string value) {
                          data += value;
                          return true;
                        });

      if (data.length() > 0) {
        static const unsigned max_length =
            1024; // Max number of bytes of data serialized, note this is input
                  // bytes, each byte will be 2 hex chars
        static const bool zero_extend =
            true; // Set to true to pad shorter data with zero up to max_length
        unsigned cur_length = 0;
        std::string data_string;
        data_string.reserve(max_length * 2);

        for (char &c : data) {
          data_string += std::format("{:02x}", c);
          if (++cur_length >= max_length)
            break;
        }

        if (zero_extend) {
          data_string = std::format("{:0<2048}", data_string);
        }

        output += data_string;
      } else {
        output += settings.blank_replace;
      }

      output += '\n';
      return output;
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
  bool is_binary() override { return false; };

  std::shared_ptr<LioLi::Serializer::Context> create_context() override {
    return std::make_shared<Context>();
  };
};

class Module : public snort::Module {
  Module() : snort::Module(s_name, s_help, module_params) {
    LioLi::LogDB::register_type<Serializer>();
  }

  bool begin(const char *, int, snort::SnortConfig *) override { return true; }

  bool end(const char *, int, snort::SnortConfig *) override { return true; }

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("item_separator")) {
      settings.separator = val.get_as_string();
      return true;
    } else if (val.is("if_item_blank_then_output")) {
      settings.blank_replace = val.get_as_string();
      return true;
    }

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

} // namespace serializer_csv
