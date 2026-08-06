#ifndef concepts_5D82E4B7
#define concepts_5D82E4B7

////////////////////////////////////////////////////////////////////////
//
// This file defines the concepts that are used for snort definitions
//
////////////////////////////////////////////////////////////////////////

// Snort includes
#include <framework/parameter.h>

// System includes
#include <string_view>

// Global includes

// Local includes

// Debug includes

namespace trout::templates {

// Concept to validate a c-style string can be extracted from the class
template <class T>
concept ConstexprGetCStringConcept = requires(const std::string_view &string) {
  { T::get_cstring() } -> std::same_as<const char *>;
  { T::is(string) } -> std::same_as<bool>;

  // Check get_cstring are consteval/consexpr
  typename std::bool_constant<(T::get_cstring(), true)>;
};

// Concept for clases that can fill snort name fields
class GenericNameBaseClass {};

template <class T>
concept NameConcept =
    ConstexprGetCStringConcept<T> && std::derived_from<T, GenericNameBaseClass>;

template <class T> struct CheckIsName : std::bool_constant<NameConcept<T>> {};

// Concept for classes that can fill snort help text fields
class GenericHelpTextBaseClass {};

template <class T>
concept HelpTextConcept = ConstexprGetCStringConcept<T> &&
                          std::derived_from<T, GenericHelpTextBaseClass>;

template <class T>
struct CheckIsHelpText : std::bool_constant<HelpTextConcept<T>> {};

} // namespace trout::templates

#endif  // #ifndef concepts_5D82E4B7
