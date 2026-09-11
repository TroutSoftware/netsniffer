#ifndef pegs_peg_75876C5E
#define pegs_peg_75876C5E

////////////////////////////////////////////////////////////////////////
//
// The Peg template is defining a peg, it's name, type and help text
//
////////////////////////////////////////////////////////////////////////

// Snort includes

// System includes

// Global includes

// Local includes
#include "concepts.h"
#include "help_text.h"
#include "name.h"
#include "pegs_concepts.h"
#include "pegs_peg_types.h"

// Debug includes

namespace trout::templates {

template <PegsElementsConcept... list> class Peg {
  [[maybe_unused]] static const auto count_of_all_elements = sizeof...(list);
  [[maybe_unused]] static const auto count_of_name_elements =
      (0 + ... + NameConcept<list>);
  [[maybe_unused]] static const auto count_of_help_text_elements =
      (0 + ... + HelpTextConcept<list>);
  [[maybe_unused]] static const auto count_of_type_elements =
      (0 + ... + PegsTypeConcept<list>);

  // Required fields
  static_assert(count_of_name_elements == 1,
                "You need to supply excactly one Name parameter");
  static_assert(count_of_help_text_elements == 1,
                "You need to supply excactly one HelpText parameter");
  static_assert(count_of_type_elements == 1,
                "You need to supply exactly one Type parameter");


  // TODO: Move generic template helpers to separate header
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

  static consteval CountType get_type() {
    return FindType<CheckIsPegsType>::get_type();
  }

  static consteval const char *get_help_text() {
    return FindType<CheckIsHelpText>::get_cstring();
  }

  // Create an instance of each of our parameters
//  std::tuple<list...> data;

public:
  // Static functions operating on the type it self
  static consteval PegInfo generate_snort_def() {
    return PegInfo{get_type(), get_name(), get_help_text()};
  }

  template <FixedString name> static consteval bool is() {
    return CStringType<name>::is(std::string_view(get_name()));
  }

  using GetTypeType = FindType<CheckIsPegsType>;

  // template <FixedString name>
  // static constexpr bool am = FindType<CheckIsName>::am<name>;

  // Non-static functions operating on instances of the type
/*
  // Function that sets the value of this parameter to val, if name matches
  bool set(const std::string_view &name, snort::Value &val) {
    if (std::get<FindType<CheckIsName>>(data).is(name)) {
      std::get<FindType<CheckIsParameterType>>(data).set(val);
      return true;
    }
    return false;
  }

  // Retrieve value, we use decltype to ensure references survive
  decltype(auto) get() { return std::get<FindType<CheckIsParameterType>>(data).get(); }
*/  
};

}; // namespace trout::templates

#endif // #ifndef pegs_peg_75876C5E

