#ifndef parameter_concepts_D9E175AC
#define parameter_concepts_D9E175AC

////////////////////////////////////////////////////////////////////////
//
// This file defines the concepts that are used for snort parameter
// definitions
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

// Concept for classes that can fill snort parameter type fields
class GenericTypeBaseClass {};

template <class T>
concept TypeConcept = std::derived_from<T, GenericTypeBaseClass> &&
                      requires(T t, snort::Value &sv) {
                        // Static function(s) called on the type

                        // The snort type used during registration
                        {
                          T::get_type()
                        } /*-> std::same_as<snort::Parameter::Type>*/;

                        // Non-static functions called on instances of the type

                        // Set function to read data from snort
                        { t.set(sv) } -> std::same_as<void>;
                        // Get function, used to retrieve the value during
                        // runtime
                        { t.get() };
                      };

template <class T> struct CheckIsType : std::bool_constant<TypeConcept<T>> {};

// Concept for classes that can fill the snort parameter default value fields
class GenericDefaultValueBaseClass {};

template <class T>
concept DefaultValueConcept =
    ConstexprGetCStringConcept<T> &&
    std::derived_from<T, GenericDefaultValueBaseClass>;

template <class T>
struct CheckIsDefaultValue : std::bool_constant<DefaultValueConcept<T>> {};

// Concept for classes that can fill the snort Parameter range fields
class GenericRangeBaseClass {};

template <class T>
concept RangeConcept = std::derived_from<T, GenericRangeBaseClass> && requires {
  { T::get_range() } -> std::same_as<void *>;

  // Check functions can be called compile time
  typename std::bool_constant<(T::get_range(), true)>;
};
;

template <class T> struct CheckIsRange : std::bool_constant<RangeConcept<T>> {};

// Concept for what can be accepted in a parameter declaration
template <class T>
concept ParamElementsConcept =
    NameConcept<T> || HelpTextConcept<T> || TypeConcept<T> ||
    DefaultValueConcept<T> || RangeConcept<T>;

// Concept for something that can generate snort::Parameter
template <class T>
concept ParameterDefinitionConcept =
    requires(T &t, const std::string_view &name, snort::Value &v) {
      {
        T::generate_snort_def()
      } -> std::same_as<snort::Parameter>; // Generates the parameter definition
      {
        T::template is<"name">()
      } -> std::same_as<bool>; // Checks if this parameter has name
      {
        t.set(name, v)
      }
      -> std::same_as<bool>; // true if name was a match and parameter consumed
      { t.get() }; // Retrive of value function, type could be anything
    };

}; // namespace trout::templates

#endif // #ifndef parameter_concepts_D9E175AC
