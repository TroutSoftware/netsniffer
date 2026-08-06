#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes
#include <framework/module.h>
#include <hash/hash_key_operations.h>
#include <protocols/packet.h>

// System includes
#include <map>
#include <string>

// Global includes

// Local includes
#include "flow_data.h"
#include "ips_option_mqtt_field.h"
#include "mqtt_protocol_defs.h"

// Debug includes
#include <iostream>

namespace mqtt_plugin {
namespace {

static const char *s_name = "mqtt_field";

static const char *s_help = "moves cursor to given field";

static const snort::Parameter module_params[] = {
    {"~", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Field requested"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

const PegInfo s_pegs[] = {
    {CountType::SUM, "invokations", "Number of times a paket was serached"},
    {CountType::SUM, "matches",
     "Number of times the field was found"},
    {CountType::END, nullptr, nullptr}};

// This must match the s_pegs[] array
THREAD_LOCAL struct PegCounts {
  PegCount invokations = 0;
  PegCount matches = 0;
} s_peg_counts;

// Compile time sanity check of number of entries in s_pegs and s_peg_counts
static_assert(
    (sizeof(s_pegs) / sizeof(PegInfo)) - 1 ==
        sizeof(PegCounts) / sizeof(PegCount),
    "Entries in s_pegs doesn't match number of entries in s_peg_counts");

using GetterFuncSignature = snort::IpsOption::EvalStatus(*)(Cursor &c, snort::Packet *p);

snort::IpsOption::EvalStatus dummyGetter(Cursor &, snort::Packet *) {
  return snort::IpsOption::NO_MATCH;
}

snort::IpsOption::EvalStatus client_id_getter(Cursor &c, snort::Packet *p) {
  PacketFlowData *flow_data = PacketFlowData::get_from_flow(p->flow);
  assert(flow_data);

  // We can only read ClientID from a Connect command
  if (flow_data->msg_type != MsgType::CONNECT) {
    return snort::IpsOption::NO_MATCH;
  }

  if ( p->flow && p->flow->gadget )
  {
      snort::Inspector* gadget = p->flow->gadget;
      snort::InspectionBuffer buf;

      if ( gadget->get_buf(s_name, p, buf) ) {
std::cerr << "MKRTEST got named buffer" << std::endl;
}
else
{
std::cerr << "MKRTEST didn't get named buffer" << std::endl;
}
}

  // Encoding depends on protocol level
  switch (flow_data->protocol_level) {
    case 3: { // MQTT 3.1
      constexpr uint32_t var_header_size = 12;      // See 3.1 spec

      if (p->dsize <= var_header_size + 2) { // payload size is at least 2 bytes
        // TODO: Mark package as invalid MQTT / truncated
std::cerr << "MKRTEST: Connect client_id truncated" << std::endl;
        return snort::IpsOption::NO_MATCH;
      }

      std::span<const uint8_t> payload(p->data+var_header_size, p->dsize-var_header_size);

      size_t read_pos = 0;
      uint32_t client_id_len = 0;
      bool success;

      std::tie(client_id_len, success) = decode_var_int(payload, read_pos);

//      flow_data->remaining_from_header;
//      flow_data->variable_header_start;
      c.set(s_name, payload.data() + read_pos, client_id_len);

      return snort::IpsOption::MATCH;
    }

    default:
      std::cerr << "MKRTEST: protocol " << flow_data->protocol_level << " not implemented for ClientID" << std::endl;
      //TODO: Add snort warning

  }

  // We found no match
  return snort::IpsOption::NO_MATCH;
}

namespace {
static const std::map<std::string, GetterFuncSignature> mqtt_field_map  {
  {"ClientID", client_id_getter}
};
} // namespace {


class Module : public snort::Module {


  GetterFuncSignature getterFunc = dummyGetter;

  Module() : snort::Module(s_name, s_help, module_params) {}

  bool begin(const char *, int, snort::SnortConfig *) override {
    getterFunc = dummyGetter;
    return true;
  }

  bool end(const char *, int, snort::SnortConfig *) override {
    return getterFunc != dummyGetter;
  }

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("~")) {
      auto field = mqtt_field_map.find(val.get_as_string());

      if (field == mqtt_field_map.end()) {
std::cerr << "MKRTEST: IPS option was not found: " << val.get_as_string() << std::endl;
        return false;
      }

      getterFunc = field->second;
      return true;
    }

    // fail if we didn't get something valid
    return false;
  }

  Usage get_usage() const override { return DETECT; }

  const PegInfo *get_pegs() const override { return s_pegs; }

  PegCount *get_counts() const override {
    return reinterpret_cast<PegCount *>(&s_peg_counts);
  }

public:
  static snort::Module *ctor() { return new Module(); }

  static void dtor(snort::Module *p) { delete p; }

  GetterFuncSignature get_getter() { return getterFunc; }
};

class IpsOption : public snort::IpsOption {

  GetterFuncSignature getterFunc;

  IpsOption(Module &module) : snort::IpsOption(s_name), getterFunc(module.get_getter()) {}

  // Hash compare is used as a fast way to compare two instances of IpsOption
  uint32_t hash() const override {
    static_assert(sizeof(getterFunc) <= 8);

    uint64_t p = static_cast<uint64_t>(reinterpret_cast<std::uintptr_t>(getterFunc));

    uint32_t a = static_cast<uint32_t>(p & 0xFFFF'FFFF);
    uint32_t b = static_cast<uint32_t>(p >> 32);
    uint32_t c = 0;

    mix(a,b,c);
    finalize(a,b,c);

    return c;
  }

  // If hashes match a real comparison check is made
  bool operator==(const snort::IpsOption &ips) const override {
    return getterFunc == dynamic_cast<const IpsOption &>(ips).getterFunc;
  }

  EvalStatus eval(Cursor &c, snort::Packet *p) override {
      return getterFunc(c, p);

    //return MATCH;
  }

  snort::CursorActionType get_cursor_type() const override {
    return snort::CAT_ADJUST;
  }

public:
  static snort::IpsOption *ctor(snort::Module *module, IpsInfo &) {
    assert(module);
    return new IpsOption(*dynamic_cast<Module *>(module));
  }

  static void dtor(snort::IpsOption *p) { delete p; }
};

} // namespace

const snort::IpsApi ips_option = {{
                                      PT_IPS_OPTION,
                                      sizeof(snort::IpsApi),
                                      IPSAPI_VERSION,
                                      0,
                                      API_RESERVED,
                                      API_OPTIONS,
                                      s_name,
                                      s_help,
                                      Module::ctor,
                                      Module::dtor,
                                  },
                                  snort::OPT_TYPE_DETECTION,
                                  0,
                                  PROTO_BIT__PDU,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  IpsOption::ctor,
                                  IpsOption::dtor,
                                  nullptr};

} // namespace mqtt_plugin
