#ifndef parameter_param_help_text_B6F41C8D
#define parameter_param_help_text_B6F41C8D

////////////////////////////////////////////////////////////////////////
//
// The parameter help text specifies the help text displayed by snort
// when help is requested on the module parameters
//
////////////////////////////////////////////////////////////////////////

// Snort includes

// System includes

// Global includes

// Local includes
#include "c_string_type.h"

// Debug includes

namespace trout::templates {

// Simple Help text class
template <FixedString help_text>
class HelpText : public CStringType<help_text>,
                 public GenericHelpTextBaseClass {};

static_assert(HelpTextConcept<HelpText<"">>,
              "HelpText is not compliant with HelpTextConcept");

}; // namespace trout::templates

#endif // #ifndef parameter_param_help_text_B6F41C8D
