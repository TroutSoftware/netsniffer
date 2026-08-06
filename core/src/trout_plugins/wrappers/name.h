#ifndef name_A7F34C91
#define name_A7F34C91

////////////////////////////////////////////////////////////////////////
//
// A name specifies an asciiz string that can be used to name an entry
// the name can typically both be used for look ups as well as defining
// it to snort
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

#endif // #ifndef name_A7F34C91
