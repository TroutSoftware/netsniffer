// Snort includes
#include <framework/data_bus.h>
#include <protocols/packet.h>
#include <pub_sub/intrinsic_event_ids.h>

// System includes

// Global includes

// Local includes
#include "flow_data.h"
#include "inspector.h"
#include "module.h"
#include "pegs.h"

// Debug includes

namespace trout_netflow2 {

namespace {

class ServiceEventHandler : public snort::DataHandler {

public:
  ServiceEventHandler() : DataHandler(Module::get_module_name()) {}

  void handle(snort::DataEvent &, snort::Flow *flow) override {
    if (flow) {
      PacketFlowData *flow_data = PacketFlowData::get_from_flow(flow);

      if (flow_data->handle && flow->service) {
        Pegs::s_peg_counts.services_seen++;
        flow_data->handle->add_service(flow->service);
      }
    }
  }
};

} // namespace

void Inspector::eval(snort::Packet *p) {
  assert(p);
  assert(cache);

  Pegs::s_peg_counts.pkts_seen++;

  if (p->flow) {
    PacketFlowData *flow_data = PacketFlowData::get_from_flow(p->flow);

    if (flow_data->handle) {
      flow_data->handle->add_sizes(p);
    } else {
      // TODO: Figure out if there is any case where a service is given in this
      // flow, that are not also being signaled
      // snort::IntrinsicEventIds::FLOW_SERVICE_CHANGE
      //       If above, then update Pegs::s_peg_counts.services_seen
      //       accordingly
      Pegs::s_peg_counts.flows_seen++;
      flow_data->handle =
          cache->create(p); // Create includes adding the first package
    }

  } else {
    Pegs::s_peg_counts.pkts_without_flow++;

    cache->add(p);
  }
}

bool Inspector::configure(snort::SnortConfig *) {
  snort::DataBus::subscribe_network(
      snort::intrinsic_pub_key, snort::IntrinsicEventIds::FLOW_SERVICE_CHANGE,
      new ServiceEventHandler());
  return true;
}

void Inspector::show(const snort::SnortConfig *) const {
  snort::ConfigLogger::log_value("flush_interval_ms",
                                 settings->get_flush_interval_ms());
  snort::ConfigLogger::log_flag("ping_mode", settings->get_do_ping());
  snort::ConfigLogger::log_value("logger_name",
                                 settings->get_logger_name().c_str());
}

Inspector::Inspector(Module *module)
    : settings(module->get_settings()),
      cache(Cache::create_cache(settings, module->get_name())) {}

Inspector::~Inspector() {
  if (!settings->get_logger()) {
    snort::ErrorMessage("ERROR: Netflow2 asked to use \"%s\" as logger, but it "
                        "never became available\n",
                        settings->get_logger_name().c_str());
  }
}

snort::Inspector *Inspector::ctor(snort::Module *module) {
  return new Inspector(dynamic_cast<Module *>(module));
}

void Inspector::dtor(snort::Inspector *p) { delete p; }

} // namespace trout_netflow2
