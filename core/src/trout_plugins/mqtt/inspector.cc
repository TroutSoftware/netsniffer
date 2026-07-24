
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes
#include <protocols/packet.h>
#include <stream/stream_splitter.h>

// System includes

// Global includes

// Local includes
#include "inspector.h"
#include "module.h"
#include "pegs.h"
#include "stream_splitter.h"

// Debug includes
#include <iostream>

namespace mqtt_plugin {

void Inspector::eval(snort::Packet *p) {
  assert(p);
  std::cerr << "MKRTEST: eval called with pkt len " << p->pktlen
            << " datalen " << p->dsize << std::endl;
}


snort::StreamSplitter* Inspector::get_splitter(bool to_server) {
  std::cerr << "MKRTEST get_splitter called with " << std::boolalpha << to_server << std::endl;
  return new StreamSplitter(to_server);
}

Inspector::Inspector(Module *module) : settings(module->get_settings()) {}

Inspector::~Inspector() {}

snort::Inspector *Inspector::ctor(snort::Module *module) {
  return new Inspector(dynamic_cast<Module *>(module));
}

void Inspector::dtor(snort::Inspector *p) { delete p; }

} // namespace mqtt_plugin
