
// Snort includes
#include <framework/decode_data.h>
#include <framework/inspector.h>
#include <framework/module.h>

// System includes
#include <iostream>
#include <mutex>

// Local includes
#include "lioli.h"
#include "output_to.h"
#include "output_to_stdout.h"

namespace output_to_stdout {
namespace {

static const char *s_name = "output_to_stdout";
static const char *s_help = "Maps treelogger output to stdout";

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

class Inspector : public snort::Inspector, public LioLi::LogStream {
  void eval(snort::Packet *) override {};

  void set_binary_mode() override {
    // stdout doesn't handle binary output
  }

  void operator<<(const std::string &&tree) override {
    static std::mutex mutex;
    std::scoped_lock lock(mutex);

    // Output under mutex protection
    std::cout << tree;
  }

  std::shared_ptr<Inspector>
      snort_ptr; // Used to keep object alive while snort uses it
public:
  static snort::Inspector *ctor(snort::Module *) {
    auto new_inspector = std::make_shared<Inspector>();
    Inspector *tmp = new_inspector.get();
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

} // namespace output_to_stdout
