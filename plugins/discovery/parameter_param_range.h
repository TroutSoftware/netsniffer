#ifndef parameter_param_range_F0C38D21
#define parameter_param_range_F0C38D21

////////////////////////////////////////////////////////////////////////
//
// The range specifies the allowable range for parameter values
// specified on the lua config script
//
////////////////////////////////////////////////////////////////////////

// Snort includes

// System includes

// Global includes

// Local includes

// Debug includes

namespace trout::templates {

// Simple range class that takes a cstring as template parameter (transfered
// directly to snort as is)
template <FixedString range_parameter>
class SimpleRange : public GenericRangeBaseClass {

public:
  static consteval void *get_range() {
    return const_cast<char *>(CStringType<range_parameter>::get_cstring());
  }
};

static_assert(RangeConcept<SimpleRange<"">>,
              "SimpleRange is not compliant with ConceptRange");

}; // namespace trout::templates

#endif // #ifndef parameter_param_range_F0C38D21
