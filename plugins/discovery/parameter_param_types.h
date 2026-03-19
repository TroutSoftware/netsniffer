#ifndef parameter_param_types_E35D8F12
#define parameter_param_types_E35D8F12

////////////////////////////////////////////////////////////////////////
//
// This file contains concrete templates for individual parameter types
// used to build a specific parameter
//
////////////////////////////////////////////////////////////////////////

// Snort includes
#include <framework/parameter.h>
#include <framework/value.h>

// System includes
#include <utility>

// Global includes

// Local includes

// Debug includes

namespace trout::templates {

// We map snorts type enum to a type safe list
enum class ParameterType {
  // Table = snort::Parameter::PT_TABLE,      // range is Parameter*, no default
  // List = snort::Parameter::PT_LIST,       // range is Parameter*, no default
  // Dynamic = snort::Parameter::PT_DYNAMIC,    // range is RangeQuery*
  Bool = snort::Parameter::PT_BOOL, // if you are reading this, get more coffee
  Int = snort::Parameter::PT_INT, // signed 53 bits or less determined by range
                                  // Interval = snort::Parameter::PT_INTERVAL,
                                  // // string that defines an interval, bounds
                                  // within range Real =
                                  // snort::Parameter::PT_REAL,       // double
                                  // Port = snort::Parameter::PT_PORT,       //
                                  // 0 to 64K-1 unless specified otherwise
  String = snort::Parameter::PT_STRING, // any string less than len chars
  // range = "(optional)" if not required (eg on cmd line)
  // Select = snort::Parameter::PT_SELECT,     // any string
  // appearing in range Multi = snort::Parameter::PT_MULTI, //
  // one or more strings appearing in range Enum =
  // snort::Parameter::PT_ENUM,       // string converted to
  // unsigned by range sequence Mac = snort::Parameter::PT_MAC,
  // // 6-byte mac address IP4 = snort::Parameter::PT_IP4, //
  // inet_addr() compatible Addr = snort::Parameter::PT_ADDR, //
  // ip4 or ip6 CIDR BitList = snort::Parameter::PT_BIT_LIST, //
  // string that converts to bitset IntList =
  // snort::Parameter::PT_INT_LIST,   // string that contains
  // ints AddrList = snort::Parameter::PT_ADDR_LIST,  // Snort 2
  // ip list in [ ] Implied = snort::Parameter::PT_IMPLIED,    //
  // rule option args w/o values eg relative StrList =
  // snort::Parameter::PT_STR_LIST,   // string that contains
  // strings
};

template <ParameterType type> class ParamStorage {
  static_assert(false, "'type' is not implemented with a storage object");
};

template <> class ParamStorage<ParameterType::Bool> {
  bool value;

public:
  void set(snort::Value &val) { value = val.get_bool(); }

  bool get() { return value; }
};

template <> class ParamStorage<ParameterType::Int> {
  int value;

public:
  void set(snort::Value &val) {

    static_assert(sizeof(value) == 4 || sizeof(value) == 8,
                  "Support only implemented for 4 and 8 byte integers");

    if constexpr (sizeof(value) == 4) {
      value = val.get_int32();
    } else if constexpr (sizeof(value) == 8) {
      value = val.get_int64();
    }
  }

  int get() { return value; }
};

template <> class ParamStorage<ParameterType::String> {
  std::string value;

public:
  void set(snort::Value &val) { value = val.get_as_string(); }

  const std::string &get() { return value; }
};

// Simple Type containing class
template <ParameterType type>
class Type : public GenericTypeBaseClass, public ParamStorage<type> {
public:
  static consteval snort::Parameter::Type get_type() {
    return static_cast<snort::Parameter::Type>(std::to_underlying(type));
  }
};

static_assert(TypeConcept<Type<ParameterType::Bool>>,
              "Type is not compliant with ConceptType");

}; // namespace trout::templates

#endif // #ifndef parameter_param_types_E35D8F12
