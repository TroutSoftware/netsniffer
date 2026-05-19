#ifndef string_from_type_AF8AB2C
#define string_from_type_AF8AB2C

////////////////////////////////////////////////////////////////////////
//
// CStringType is a type defined by an asciiz string, the string can be
// retreived as a string_view string, a FixedString is used as way to
// make the string part of the type (compile time)
//
////////////////////////////////////////////////////////////////////////

// Snort includes

// System includes
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <string_view>

// Global includes

// Local includes
#include "parameter_concepts.h"

// Debug includes

namespace trout::templates {

template <std::size_t N> struct FixedString {
  char data[N]{};

  constexpr FixedString(const char (&str)[N]) {
    assert(N > 0 && str[N - 1] == 0 && "String must be zero terminated");
    std::copy_n(str, N, data);
  }
};

// Template class that holds a string
template <FixedString str> struct CStringType {
  static consteval const char *get_cstring() { return str.data; }
  static constexpr bool is(const std::string_view &cs) {
    constexpr std::string_view my_value(get_cstring());
    return cs == my_value;
  }

  // template <FixedString name>
  // static constexpr bool am = (str == name);
};

static_assert(ConstexprGetCStringConcept<CStringType<"">>,
              "CStringType doesn't comply to intended concept");

}; // namespace trout::templates

#endif // #ifndef string_from_type_AF8AB2C
