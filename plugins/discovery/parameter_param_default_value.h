#ifndef parameter_param_default_value_2E7B5A90
#define parameter_param_default_value_2E7B5A90

////////////////////////////////////////////////////////////////////////
//
// The parameter default value specifies the default value used to
// set the value of a parameter that is not set explicitly in the
// lua config script
//
////////////////////////////////////////////////////////////////////////

// Snort includes

// System includes

// Global includes

// Local includes
#include "c_string_type.h"

// Debug includes

namespace trout::templates {

// Simple default value class
template <FixedString default_parameter>
class DefaultValue : public CStringType<default_parameter>,
                     public GenericDefaultValueBaseClass {};

static_assert(DefaultValueConcept<DefaultValue<"">>,
              "DefaultValue is not compliant with DefaultValueConcept");

}; // namespace trout::templates

#endif // #ifndef parameter_param_default_value_2E7B5A90
