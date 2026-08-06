#ifndef help_text_C31A7F52
#define help_text_C31A7F52

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

#endif // #ifndef help_text_C31A7F52
