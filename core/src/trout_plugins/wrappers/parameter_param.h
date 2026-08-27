#ifndef parameter_param_882F60D4
#define parameter_param_882F60D4

////////////////////////////////////////////////////////////////////////
//
// The Param template is defining a non-specialized parameter (ie. a
// standard parameter, like a bool, integer etc.., but not like a
// logger, or other "inteligent" parameters)
//
////////////////////////////////////////////////////////////////////////

// Snort includes

// System includes

// Global includes

// Local includes
#include "concepts.h"
#include "name.h"
#include "help_text.h"
#include "parameter_concepts.h"
#include "parameter_param_default_value.h"
#include "parameter_param_range.h"
#include "parameter_param_types.h"

// Debug includes

namespace trout::templates {

template <ParamElementsConcept... list> class Param {
  [[maybe_unused]] static const auto count_of_all_elements = sizeof...(list);
  [[maybe_unused]] static const auto count_of_name_elements =
      (0 + ... + NameConcept<list>);
  [[maybe_unused]] static const auto count_of_help_text_elements =
      (0 + ... + HelpTextConcept<list>);
  [[maybe_unused]] static const auto count_of_type_elements =
      (0 + ... + TypeConcept<list>);
  [[maybe_unused]] static const auto count_of_default_value_elements =
      (0 + ... + DefaultValueConcept<list>);
  [[maybe_unused]] static const auto count_of_range_elements =
      (0 + ... + RangeConcept<list>);

  // Required fields
  static_assert(count_of_name_elements == 1,
                "You need to supply excactly one Name parameter");
  static_assert(count_of_help_text_elements == 1,
                "You need to supply excactly one HelpText parameter");
  static_assert(count_of_type_elements == 1,
                "You need to supply exactly one Type parameter");

  // Optional fields
  static_assert(count_of_default_value_elements <= 1,
                "You can't specify more than one default parameter");
  static_assert(count_of_range_elements <= 1,
                "You can't supply more than one range parameter");

  // Templates for finding specific element type
  template <template <typename> class Predicate, typename... Ts>
  struct FindMatch {
    static_assert(false, "FindMatch couldn't find the type requested");
  };

  template <template <typename> class Predicate, typename T, typename... Rest>
  struct FindMatch<Predicate, T, Rest...>
      : std::conditional_t<Predicate<T>::value, std::type_identity<T>,
                           FindMatch<Predicate, Rest...>> {};

  template <template <typename> class Predicate>
  using FindType = typename FindMatch<Predicate, list...>::type;

  // Extractor functions for elements where we from the preconditions know there
  // must be exactly one of
  static consteval const char *get_name() {
    return FindType<CheckIsName>::get_cstring();
  }

  static consteval snort::Parameter::Type get_type() {
    return FindType<CheckIsType>::get_type();
  }

  static consteval const char *get_help_text() {
    return FindType<CheckIsHelpText>::get_cstring();
  }

  // Extractor functions for elements where we might need a default value and
  // know there can only be one
  static consteval void *get_range() {
    if constexpr (count_of_range_elements) {
      return FindType<CheckIsRange>::get_range();
    } else {
      return nullptr;
    }
  }

  static consteval const char *get_default_value() {
    if constexpr (count_of_default_value_elements) {
      return FindType<CheckIsDefaultValue>::get_cstring();
    } else {
      return nullptr;
    }
  }

  // Create an instance of each of our parameters
  std::tuple<list...> data;

public:
  // Static functions operating on the type it self

  static snort::Parameter generate_snort_def() {
    return snort::Parameter{get_name(), get_type(), get_range(),
                            get_default_value(), get_help_text()};
  }

  template <FixedString name> static consteval bool is() {
    return CStringType<name>::is(std::string_view(get_name()));
  }

  // template <FixedString name>
  // static constexpr bool am = FindType<CheckIsName>::am<name>;

  // Non-static functions operating on instances of the type

  // Function that sets the value of this parameter to val, if name matches
  bool set(const std::string_view &name, snort::Value &val) {
    if (std::get<FindType<CheckIsName>>(data).is(name)) {
      std::get<FindType<CheckIsType>>(data).set(val);
      return true;
    }
    return false;
  }

  // Retrieve value, we use decltype to ensure references survive
  decltype(auto) get() { return std::get<FindType<CheckIsType>>(data).get(); }
};

}; // namespace trout::templates

#endif // #ifndef parameter_param_882F60D4
