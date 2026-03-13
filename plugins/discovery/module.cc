
// TODO: This file is heavily WIP....

// Snort includes

// System includes

// Global includes

// Local includes
#include "module.h"
#include "pegs.h"

// Debug includes
#include <algorithm>
#include <array>
#include <compare>
#include <concepts>
#include <format>
#include <string>
#include <utility>

// Anonomous namespace, i.e. internal linking (won't interfere with things
// outside of this file)
namespace {

const char *s_name =
    "discovery"; // TODO: Replace with the name of the plugin
const char *s_help =
    "Help text for plugin"; // TODO: Replace with help text for your plugin


template <std::size_t N>
struct FixedString {
    char data[N]{};

    constexpr FixedString(const char (&str)[N]) {
      assert(N>0 && str[N-1] == 0 && "String must be zero terminated");
      std::copy_n(str, N, data);
    }
};

//template <std::size_t N> FixedString(const char (&)[N]) -> FixedString<N>;

// Concept to validate a c-style string can be extracted from the class
template <class T>
concept HasConstexprCString = requires {
  { T::get_cstring() } -> std::same_as<const char *>;

  // Check the get_cstring() function is consteval/consexpr
  typename std::bool_constant<(T::get_cstring(), true)>;
};


// Template class that holds a string
template <FixedString str>
struct StringExtractor {
    static consteval const char* get_cstring() {return str.data;}
};

static_assert(HasConstexprCString<StringExtractor<"">>, "StringExtractor doesn't comply to intended concept");


// Testcode
using myPar = StringExtractor<"my help text">;

// We map snorts type enum to a type safe list
// TODO: Move
enum class ParameterType
{
    Table = snort::Parameter::PT_TABLE,      // range is Parameter*, no default
    List = snort::Parameter::PT_LIST,       // range is Parameter*, no default
    Dynamic = snort::Parameter::PT_DYNAMIC,    // range is RangeQuery*
    Bool = snort::Parameter::PT_BOOL,       // if you are reading this, get more coffee
    Int = snort::Parameter::PT_INT,        // signed 53 bits or less determined by range
    Interval = snort::Parameter::PT_INTERVAL,   // string that defines an interval, bounds within range
    Real = snort::Parameter::PT_REAL,       // double
    Port = snort::Parameter::PT_PORT,       // 0 to 64K-1 unless specified otherwise
    String = snort::Parameter::PT_STRING,     // any string less than len chars
                   // range = "(optional)" if not required (eg on cmd line)
    Select = snort::Parameter::PT_SELECT,     // any string appearing in range
    Multi = snort::Parameter::PT_MULTI,      // one or more strings appearing in range
    Enum = snort::Parameter::PT_ENUM,       // string converted to unsigned by range sequence
    Mac = snort::Parameter::PT_MAC,        // 6-byte mac address
    IP4 = snort::Parameter::PT_IP4,        // inet_addr() compatible
    Addr = snort::Parameter::PT_ADDR,       // ip4 or ip6 CIDR
    BitList = snort::Parameter::PT_BIT_LIST,   // string that converts to bitset
    IntList = snort::Parameter::PT_INT_LIST,   // string that contains ints
    AddrList = snort::Parameter::PT_ADDR_LIST,  // Snort 2 ip list in [ ]
    Implied = snort::Parameter::PT_IMPLIED,    // rule option args w/o values eg relative
    StrList = snort::Parameter::PT_STR_LIST,   // string that contains strings
    //PT_MAX
};


// Generic trap for public inheritance
/*
template <template <typename...> class Base, typename... Ts>
void template_base_trap(const Base<T...>*);
*/

// Generic concept for checking inheritance to template classes
/*
template <typename T, template <typename...> class Base>
concept IsOrDerivedFromTemplate = requires(const T* ptr) {
  template_base_trap<Base>(ptr);
};
*/

// Concept for clases that can fill snort parameter name fields
class GenericNameBaseClass {};

template <class T>
concept ConceptName = HasConstexprCString<T> && std::derived_from<T, GenericNameBaseClass>;

template <class T>
struct CheckIsName : std::bool_constant<ConceptName<T>> {};

// Concept for classes that can fill snort parameter help text fields
class GenericHelpTextBaseClass {};

template <class T>
concept ConceptHelpText = HasConstexprCString<T> && std::derived_from<T, GenericHelpTextBaseClass>;

template <class T>
struct CheckIsHelpText : std::bool_constant<ConceptHelpText<T>> {};


// Concept for classes that can fill snort parameter type fields
class GenericTypeBaseClass {};

template <class T>
concept ConceptType = std::derived_from<T, GenericTypeBaseClass> && requires {
    { T::get_type() } -> std::same_as<ParameterType>;
    //{ T::get_snort_type() } -> std::same_as<std::underlying_type_t<snort::Parameter::Type>>;
    { T::get_snort_type() } -> std::same_as<snort::Parameter::Type>;

    // Check functions can be called compile time
    typename std::bool_constant<(T::get_type(), T::get_snort_type(), true)>;
};

template <class T>
struct CheckIsType : std::bool_constant<ConceptType<T>> {};

// Concept for classes that can fill the snort parameter default value fields
class GenericDefaultValueBaseClass {};

template <class T>
concept ConceptDefaultValue = HasConstexprCString<T> && std::derived_from<T, GenericDefaultValueBaseClass>;

template <class T>
struct CheckIsDefaultValue : std::bool_constant<ConceptDefaultValue<T>> {};


// Concept for classes that can fill the snort Parameter range fields
class GenericRangeBaseClass {};

template <class T>
concept ConceptRange = std::derived_from<T, GenericRangeBaseClass> && requires {
    { T::get_range() } -> std::same_as<void *>;

    // Check functions can be called compile time
    typename std::bool_constant<(T::get_range(), true)>;
};;

template <class T>
struct CheckIsRange : std::bool_constant<ConceptRange<T>> {};


// Concept for what can be accepted in a parameter declaration
template <class T>
concept ParamElements = ConceptName<T> || ConceptHelpText<T> || ConceptType<T> || ConceptDefaultValue<T> || ConceptRange<T>;

template <ParamElements... list>
class Param {
  [[maybe_unused]] static const auto count_of_all_elements = sizeof...(list);
  [[maybe_unused]] static const auto count_of_name_elements = (0 + ... + ConceptName<list>);
  [[maybe_unused]] static const auto count_of_help_text_elements = (0 + ... + ConceptHelpText<list>);
  [[maybe_unused]] static const auto count_of_type_elements = (0 + ... + ConceptType<list>);
  [[maybe_unused]] static const auto count_of_default_value_elements = (0 + ... + ConceptDefaultValue<list>);
  [[maybe_unused]] static const auto count_of_range_elements = (0 + ... + ConceptRange<list>);

  // Required fields
  static_assert(count_of_name_elements == 1, "You need to supply excactly one Name parameter");
  static_assert(count_of_help_text_elements == 1, "You need to supply excactly one HelpText parameter");
  static_assert(count_of_type_elements == 1, "You need to supply exactly one Type paramer");

  // Optional fields
  static_assert(count_of_default_value_elements <= 1, "You can't specify more than one default parameter");
  static_assert(count_of_range_elements <= 1, "You can't supply more than one range parameter");

  // Templates for finding specific element type
  template <template <typename> class Predicate, typename... Ts>
  struct FindMatch;

  template <template <typename> class Predicate, typename T, typename... Rest>
  struct FindMatch<Predicate, T, Rest...>
      : std::conditional_t<Predicate<T>::value, std::type_identity<T>,
                           FindMatch<Predicate, Rest...>> {};

  template <template <typename> class Predicate>
  using FindType = typename FindMatch<Predicate, list...>::type;

  // Extractor functions for elements where we from the preconditions know there must be exactly one of
  static consteval const char* get_name() {
    return FindType<CheckIsName>::get_cstring();
  }

  static consteval snort::Parameter::Type get_type() {
    return FindType<CheckIsType>::get_snort_type();
  }

  static consteval const char* get_help_text() {
    return FindType<CheckIsHelpText>::get_cstring();
  }

  // Extractor functions for elements where we might need a default value and know there can only be one
  static consteval void* get_range() {
    if constexpr (count_of_range_elements) {
      return FindType<CheckIsRange>::get_range();
    } else {
      return nullptr;
    }
  }

  static consteval const char* get_default_value() {
    if constexpr (count_of_default_value_elements) {
      return FindType<CheckIsDefaultValue>::get_cstring();
    } else {
      return nullptr;
    }
  }

public:

  static snort::Parameter generate() {
    return snort::Parameter {
      get_name(),
      get_type(),
      get_range(),
      get_default_value(),
      get_help_text()};
  }
};

// Concept for something that can generate snort::Parameter
template <class T>
concept ConceptSnortParameterGenerator = requires {
  { T::generate() } -> std::same_as<snort::Parameter>;
};

template <ConceptSnortParameterGenerator... list>
class ParamList {
  public:
    static const snort::Parameter* generate() {
      static const std::array parameterList
      {
        list::generate()...,   // Expands the list for all parameters

        // Snort needs a "null" entry as the last to know when it has reached the end of the list
        snort::Parameter(nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr)
      };
      return parameterList.data();
    }
};


// Simple Name class
template <FixedString name>
class Name : public StringExtractor<name>, public GenericNameBaseClass {};

static_assert(ConceptName<Name<"">>, "Name is not compliant with ConceptName");

// Simple Help text class
template <FixedString help_text>
class HelpText : public StringExtractor<help_text>, public GenericHelpTextBaseClass {};

static_assert(ConceptHelpText<HelpText<"">>, "HelpText is not compliant with ConceptHelpText");

// Simple Type containing class
template <ParameterType type>
class Type : public GenericTypeBaseClass {
public:
  static consteval ParameterType get_type() {return type;}
  static consteval snort::Parameter::Type get_snort_type() {return static_cast<snort::Parameter::Type>(std::to_underlying(type));}
};

static_assert(ConceptType<Type<ParameterType::Bool>>, "Type is not compliant with ConceptType");

// Simple default value class
template <FixedString default_parameter>
class DefaultValue : public StringExtractor<default_parameter>, public GenericDefaultValueBaseClass {};

static_assert(ConceptDefaultValue<DefaultValue<"">>, "DefaultValue is not compliant with ConceptDefaultValue");


// Simple range class that takes a cstring as template parameter (transfered directly to snort as is)
template <FixedString range_parameter>
class SimpleRange : public GenericRangeBaseClass {

  public:
    static consteval void *get_range() {
      return const_cast<char*>(StringExtractor<range_parameter>::get_cstring());
    }
};

static_assert(ConceptRange<SimpleRange<"">>, "SimpleRange is not compliant with ConceptRange");

// TODO ranges returning snort::Parameter::RangeQuery* etc...

//template <class T>
//concept IsRange = IsSimpleRangeValue<T>; // || IsRangeQuery || etc...
/*
using MyParam = Param<Name<"template_generated">,
                      HelpText<"My help text">,
                      Type<ParameterType::List>
                     >;
*/
using MyParamList = ParamList<Param<  Name<"first_parameter">,
                                      Type<ParameterType::Bool>,
                                      DefaultValue<"true">,
                                      HelpText<"The first parameter">>,
                              Param<  Name<"second_parameter">,
                                      Type<ParameterType::Int>,
                                      SimpleRange<"1:100">,
                                      HelpText<"My second parameter">>>;

// TODO: Sample parameteres, replace with your own
/*
const snort::Parameter module_params[] = {
    {"logger", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Set logger output should be sent to"},
    {"testmode", snort::Parameter::PT_BOOL, nullptr, "false",
     "Testmode will make deterministic (fake) timestamps"},
    {"testvar", snort::Parameter::PT_BOOL, nullptr, "false", myPar::get_cstring() },
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};
*/
} // namespace

namespace trout::discovery {

// TODO: All of this tedious parameter passing should be generated by the template code
bool Module::begin(const char *, int, snort::SnortConfig *) {
  settings = std::make_shared<Settings>();
  return true;
}

bool Module::end(const char *, int, snort::SnortConfig *) { return true; }

bool Module::set(const char *, snort::Value &val, snort::SnortConfig *) {
  // TODO: Update this so it matches the actual parameters in module_params[]
  if (val.is("logger") && val.get_as_string().size() > 0) {
    settings->logger_name = val.get_as_string();
  } else if (val.is("testmode")) {
    settings->testmode = val.get_bool();
  } else {
    // fail if we didn't get something we knew about
    return false;
  }

  return true;
}

const PegInfo *Module::get_pegs() const { return Pegs::s_pegs; }

PegCount *Module::get_counts() const {
  return reinterpret_cast<PegCount *>(&Pegs::s_peg_counts);
}

Module::Module()
    : snort::Module(get_module_name(), get_module_help(), MyParamList::generate()) {}

Module::~Module() {}

Module::Usage Module::get_usage() const { return INSPECT; }

const char *Module::get_module_name() { return s_name; }

const char *Module::get_module_help() { return s_help; }

std::shared_ptr<Settings> Module::get_settings() { return settings; }

} // namespace trout::discovery
