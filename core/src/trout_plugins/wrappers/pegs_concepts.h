#ifndef pegs_concepts_F6A7BF58
#define pegs_concepts_F6A7BF58

////////////////////////////////////////////////////////////////////////
//
// This file defines the concepts that are used for snort parameter
// definitions
//
////////////////////////////////////////////////////////////////////////

// Snort includes
#include <framework/counts.h>

// System includes
#include <concepts>
#include <string_view>

// Global includes

// Local includes
#include "concepts.h"

// Debug includes

namespace trout::templates {

// Concept for classes that can fill snort parameter type fields
template <class T>
concept PegsTypeConcept = TypeConcept<T> && requires {
  // Static function(s) called on the type

  // The snort type used during registration
  { T::get_type() } -> std::same_as<CountType>;
} && std::constructible_from<T, PegCount &>;

template <class T>
struct CheckIsPegsType : std::bool_constant<PegsTypeConcept<T>> {};

// Concept for what can be accepted in a parameter declaration
template <class T>
concept PegsElementsConcept =
    NameConcept<T> || HelpTextConcept<T> || PegsTypeConcept<T>;

// Concept for something that can generate snort::Parameter
template <class T>
concept PegDefinitionConcept = requires(T &t, const std::string_view &name,
                                        snort::Value &v) {
  {
    T::generate_snort_def()
  } -> std::same_as<PegInfo>; // Generates the peg definition
  {
    T::template is<"name">()
  } -> std::same_as<bool>; // Checks if this parameter has name
  typename T::GetTypeType; // Checks it has a type defined a get should return
                           /*      {
                                   t.set(name, v)
                                 }
                                 -> std::same_as<bool>; // true if name was a match and parameter
                              consumed                          { t.get() }; // Retrive of value
                              function, type could be anything
                           */
};

}; // namespace trout::templates

#endif // #ifndef pegs_concepts_F6A7BF58
