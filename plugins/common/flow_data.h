#ifndef flow_data_17e351d7
#define flow_data_17e351d7

// Snort includes

// System includes

// Local includes

// Global includes

// Debug includes

namespace Common {

template <class T> class FlowData : public snort::FlowData, public T {

public:
  FlowData() : snort::FlowData(get_id()) {}

  unsigned static get_id() {
    static unsigned flow_data_id = snort::FlowData::create_flow_data_id();
    return flow_data_id;
  }

  static FlowData *get_from_flow(snort::Flow *flow) {
    assert(flow);

    FlowData *flow_data =
        dynamic_cast<FlowData *>(flow->get_flow_data(FlowData::get_id()));

    if (!flow_data) {
      flow_data = new FlowData();
      flow->set_flow_data(flow_data);
    }

    return flow_data;
  }
};

} // namespace Common 
#endif // #ifndef flow_data_17e351d7
