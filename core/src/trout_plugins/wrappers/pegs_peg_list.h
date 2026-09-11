#ifndef pegs_peg_list_D34DFC42
#define pegs_peg_list_D34DFC42

////////////////////////////////////////////////////////////////////////
//
// ParamList is a colection of the individual parameters that makes up
// the parameters a module can accept
//
////////////////////////////////////////////////////////////////////////

// Snort includes

// System includes

// Global includes

// Local includes
#include "pegs_concepts.h"
#include "pegs_peg.h"

// Debug includes

namespace trout::templates {
template <PegDefinitionConcept... list> class PegList {
  static const auto count_of_all_pegs = sizeof...(list);

  static_assert(count_of_all_pegs > 0, "You must specify at least one peg in a PegList");
//  std::tuple<list...>
//      data; // Stores the actual parameters, and any state associated with it

  // TODO: Move generic helper template to separate header
  template <FixedString name, typename... Ts> struct FindParameter {
    static_assert(false, "Couldn't find parameter name in defined list");
  };

  template <FixedString name, typename T, typename... Rest>
  struct FindParameter<name, T, Rest...>
      : std::conditional_t<T::template is<name>(), std::type_identity<T>,
                           FindParameter<name, Rest...>> {};

  template <FixedString name>
  using FindParameterType = typename FindParameter<name, list...>::type;

  template <FixedString name, size_t index, typename T, typename... remaining> static consteval size_t recursive_find_index() {
    if constexpr (T::template is<name>()) {
      return index;
    } else if constexpr (sizeof...(remaining) > 0) {
      return recursive_find_index<name, index + 1, remaining...>();
    } else {
      static_assert(false, "Couldn't find a peg with that name");
    }
  }


public:
  static const PegInfo *generate_snort_peg_info_def() {
    static const std::array parameterList{
        list::generate_snort_def()..., // Expands the list for all parameters

        // Snort needs an end entry as the last to know when it has reached
        // the end of the list
        PegInfo(CountType::END, nullptr, nullptr)};
    return parameterList.data();
  }

  // TODO: Be clever about worker threads here
  static PegCount *generate_snort_peg_count_def() {
    static thread_local PegCount peg_counts[count_of_all_pegs];
    return peg_counts;
  }

  //template <FixedString name> decltype(auto) get() {
  template <FixedString name> static auto get() {    
    using PegToFind = FindParameterType<name>;
    using PegType = PegToFind::GetTypeType;

    size_t index = get_index<name>();

    return PegType(generate_snort_peg_count_def()[index]);
    
    //return std::get<TypeToFind>(data).get();
  }

  template <FixedString name> static consteval size_t get_index() {
    return recursive_find_index<name, 0, list...>();
  }
};

}; // namespace trout::templates

#endif // #ifndef pegs_peg_list_D34DFC42
