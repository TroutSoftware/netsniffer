#ifndef type_C9DDD72F
#define type_C9DDD72F

////////////////////////////////////////////////////////////////////////
//
// A trout::templates::Type is a place holder for specialized types used
// to construct snort parameters, pegs, ...
//
////////////////////////////////////////////////////////////////////////

// Snort includes

// System includes

// Global includes

// Local includes
#include "concepts.h"

// Debug includes

namespace trout::templates {

// Simple Type class
template <auto>
class Type : public GenericTypeBaseClass {
  static_assert(false, "'type' is not implemented for the specified type/value, did you forget to include the correct header file?");
};



}; // namespace trout::templates

#endif // #ifndef type_C9DDD72F
