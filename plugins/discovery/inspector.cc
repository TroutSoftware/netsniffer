// Snort includes
#include <protocols/packet.h>

// System includes

// Global includes

// Local includes
#include "inspector.h"
#include "module.h"
#include "pegs.h"

// Debug includes

namespace trout::discovery {

void Inspector::eval(snort::Packet * /*p*/) {}

Inspector::Inspector(Module *module) : settings(module->get_settings()) {}

Inspector::~Inspector() {}

snort::Inspector *Inspector::ctor(snort::Module *module) {
  return new Inspector(dynamic_cast<Module *>(module));
}

void Inspector::dtor(snort::Inspector *p) { delete p; }

} // namespace trout::discovery
