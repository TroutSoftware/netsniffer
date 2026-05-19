#ifndef parameter_param_name_7C0A9B5E
#define parameter_param_name_7C0A9B5E

////////////////////////////////////////////////////////////////////////
//
// The parameter name specifies the name used to define an individual
// parameter used when building a specific parameter
//
////////////////////////////////////////////////////////////////////////

// Snort includes

// System includes

// Global includes

// Local includes
#include "c_string_type.h"

// Debug includes

namespace trout::templates {

// Simple Name class
template <FixedString name>
class Name : public CStringType<name>, public GenericNameBaseClass {};

static_assert(NameConcept<Name<"">>, "Name is not compliant with NameConcept");

}; // namespace trout::templates

#endif // #ifndef parameter_param_name_7C0A9B5E
