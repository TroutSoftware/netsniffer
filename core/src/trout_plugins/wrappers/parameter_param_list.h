#ifndef parameter_param_list_1A9C4E7B
#define parameter_param_list_1A9C4E7B

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
#include "parameter_concepts.h"

// Debug includes

namespace trout::templates {
template <ParameterDefinitionConcept... list> class ParamList {

  std::tuple<list...>
      data; // Stores the actuall parameters, and any state associated with it

  template <FixedString name, typename... Ts> struct FindParameter {
    static_assert(false, "Couldn't find parameter name in defined list");
  };

  template <FixedString name, typename T, typename... Rest>
  struct FindParameter<name, T, Rest...>
      : std::conditional_t<T::template is<name>(), std::type_identity<T>,
                           FindParameter<name, Rest...>> {};

  template <FixedString name>
  using FindParameterType = typename FindParameter<name, list...>::type;

public:
  static const snort::Parameter *generate_snort_def() {
    static const std::array parameterList{
        list::generate_snort_def()..., // Expands the list for all parameters

        // Snort needs a "null" entry as the last to know when it has reached
        // the end of the list
        snort::Parameter(nullptr, snort::Parameter::PT_MAX, nullptr, nullptr,
                         nullptr)};
    return parameterList.data();
  }

  bool set(const char *name, snort::Value &val) {
    const std::string_view sname(name);
    return (std::get<list>(data).set(sname, val) || ...);
  }

  template <FixedString name> decltype(auto) get() {
    using TypeToFind = FindParameterType<name>;
    return std::get<TypeToFind>(data).get();
  }
};

}; // namespace trout::templates

#endif // #ifndef parameter_param_list_1A9C4E7B
