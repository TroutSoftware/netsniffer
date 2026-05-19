#ifndef cache_concepts_B2F89F5A
#define cache_concepts_B2F89F5A

// Snort includes

// System includes
#include <concepts>
#include <cstdint>
#include <mutex>

// Global includes

// Local includes

// Debug includes

namespace trout_netflow2 {

////////////////////////////////////////////////////////////////////////
//  Base types & concepts
////////////////////////////////////////////////////////////////////////

// Helper stand in for an iterator
struct ConceptITR {};

// Classes inheriting from this are streamable/serializable
// A streamable class must have at least these functions:
//   consteval static uint16_t field_type_in_h()
//     -- Returns the type of the field in the RFC rfc3954 sense
//   consteval static bool is_fixed_size()
//     -- Returns true if the value should always be encoded with the same size
//   consteval static uint16_t get_max_encoded_size()
//     -- The max size (or only size for fixed size entries) of the entry
//   static uint16_t append_value(std::string &output, <iterator> &itr)
//     -- Function taking an iterator and serializing what it references to a
//     bytestream, returns size of what it added
//   static void clear_if_volatile(<iterator> &)
//     -- Function that clears variables (if needed) after serialization
class IsStreamable {};

template <class T, class ITR = ConceptITR>
concept ConceptIsStreamableVarSize = std::derived_from<T, IsStreamable> &&
                                     requires(std::string &output, ITR &itr) {
                                       {
                                         T::field_type_in_h()
                                       } -> std::same_as<uint16_t>;
                                       {
                                         T::is_fixed_size()
                                       } -> std::same_as<bool>;
                                       {
                                         T::get_max_encoded_size()
                                       } -> std::same_as<uint16_t>;
                                       {
                                         T::append_value(output, itr)
                                       } -> std::same_as<uint16_t>;
                                       {
                                         T::clear_if_volatile(itr)
                                       } -> std::same_as<void>;
                                     };

// Genric concept for streamble entries
template <class T>
concept ConceptIsStreamable = ConceptIsStreamableVarSize<T>;

// Classes inheriting from this is the mutex
// A mutex class, is one that lets the framework get the mutex of a specific
// element. The mutex will be taken by the framework before append_value and
// clear_if_volatile are called on the streamable class A mutex class must at
// last contain this function:
//   static std::mutex &get_mutex(<iterator> &itr)
//     -- returns a referenct to a standard mutex object for object the iterator
//     points to
class IsMutex {};

// Concept for mutex element
template <class T>
concept ConceptIsMutex =
    std::derived_from<T, IsMutex> && requires(ConceptITR &itr) {
      { T::get_mutex(itr) } -> std::same_as<std::mutex &>;
    };

// Helper trait
template <class T>
struct CheckIsMutex : std::bool_constant<ConceptIsMutex<T>> {};

// Class inheriting from this is a dirty flag
// A dirty class, is one that lets the framework check the dirty state of a
// specific element If a dirty definition is pressent, it won't be serialized
// unless the dirty state is true A dirty calss must at least contain this
// function:
//   static bool &get_dirty(auto &itr)
//     -- returns true if the iterator points to a dirty value, false otherwise
class IsDirty {};

// Concept for dirty element
template <class T>
concept ConceptIsDirty = requires(ConceptITR &itr) {
  { T::get_dirty(itr) } -> std::same_as<bool &>;
};

// Helper trait
template <class T>
struct CheckIsDirty : std::bool_constant<ConceptIsDirty<T>> {};

// Collection of concepts that is used to define a netflow template
template <class T>
concept ConceptNetflowDefinition =
    ConceptIsStreamable<T> || ConceptIsMutex<T> || ConceptIsDirty<T>;

} // namespace trout_netflow2

#endif // #ifndef cache_concepts_B2F89F5A
