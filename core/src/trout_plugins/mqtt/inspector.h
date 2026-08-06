#ifndef inspector_8F24C6A1
#define inspector_8F24C6A1

// Snort includes
#include <detection/detection_engine.h>
#include <framework/inspector.h>

// System includes
#include <memory>
#include <string>

// Global includes

// Local includes
#include "flow_data.h"
#include "rules.h"

// Debug includes
#include<iostream>

namespace mqtt_plugin {
class Module;
class Settings;

class Inspector : public snort::Inspector {
private:
  std::shared_ptr<Settings> settings;


  bool get_buf(snort::InspectionBuffer::Type /*ibt*/, snort::Packet* /*p*/, snort::InspectionBuffer& /*b*/) override
    { std::cerr << "MKRTEST get_buf called" << std::endl; return false;}
  bool get_buf(unsigned id, snort::Packet* /*p*/, snort::InspectionBuffer& /*b*/) override
    { std::cerr << "MKRTEST get_buf called (id=" << id << ")" << std::endl; return true;}

  void queue(SID sid) { snort::DetectionEngine::queue_event(gid, U(sid)); }

  void eval(snort::Packet *) override;
  void clear(snort::Packet*) override;

  snort::StreamSplitter* get_splitter(bool to_server) override;

  // Used to reject the packet as being MQTT
  void reject(snort::Packet *, std::string reason);

  void decode_connect(snort::Packet *p, PacketFlowData *flow_data);

public:
  Inspector(Module *module);
  ~Inspector();

  static snort::Inspector *ctor(snort::Module *module);
  static void dtor(snort::Inspector *p);
};

} // namespace mqtt_plugin

#endif // #ifndef inspector_8F24C6A1
