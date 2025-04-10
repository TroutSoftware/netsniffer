#ifndef flow_data_17e351d7
#define flow_data_17e351d7

// Snort includes

// System includes

// Local includes

// Global includes

// Debug includes

namespace Common {

// The Common::FlowData template class takes care of registering an ID
// and creating/retreiving flow data from a packet - note that the
// class given to Common::FlowData as the template class is what the
// ID is based on, e.g. to get a unique flowdata type, you need to give
// a unique type as template class

template <class T> class FlowData : public snort::FlowData, public T {
private:

  unsigned static get_id() {
    static unsigned flow_data_id = snort::FlowData::create_flow_data_id();
    return flow_data_id;
  }

  FlowData() : snort::FlowData(get_id()) {}

public:

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
