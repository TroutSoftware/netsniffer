// Snort includes
#include <protocols/packet.h>

// System includes

// Global includes

// Local includes
#include "inspector.h"
#include "module.h"
#include "pegs.h"

// Debug includes
#include <iostream>

namespace trout::discovery {

void Inspector::eval(snort::Packet * /*p*/) {}

Inspector::Inspector(Module *module) : settings(module->get_settings()) {
  // Test settings retrieval
  if (settings->get<"first_parameter">()) {
    std::cerr << "MKRTEST: First parameter_value is true" << std::endl;
  } else {
    std::cerr << "MKRTEST: First parameter_value is false" << std::endl;
  }

  std::cerr << "MKRTEST: Second paramer is: "
            << settings->get<"second_parameter">() << std::endl;
}

Inspector::~Inspector() {}

snort::Inspector *Inspector::ctor(snort::Module *module) {
  return new Inspector(dynamic_cast<Module *>(module));
}

void Inspector::dtor(snort::Inspector *p) { delete p; }

} // namespace trout::discovery
