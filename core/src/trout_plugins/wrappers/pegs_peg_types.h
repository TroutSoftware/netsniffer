#ifndef pegs_peg_types_BA01A782
#define pegs_peg_types_BA01A782

////////////////////////////////////////////////////////////////////////
//
// This file contains concrete templates for individual peg types
// used to build a specific peg
//
////////////////////////////////////////////////////////////////////////

// Snort includes
#include <framework/counts.h>

// System includes
#include <utility>

// Global includes

// Local includes
#include "concepts.h"
#include "type.h"

// Debug includes

namespace trout::templates {

// We map snorts peg type enum to a type safe list
enum class PegType {
  // END,   // sentinel value
  SUM = CountType::SUM,   // running total: tracks cumulative total number of items seen (eg #events)
  NOW = CountType::NOW,   // current level: gives snapshot of current number of items (eg current #sessions)
  MAX = CountType::MAX,   // maximum level: tracks maximum value seen (eg max #sessions)
};

/*
template <PegType type> class PegStorage {
  static_assert(false, "'type' is not implemented with a storage object");
};

template <> class PegStorage<ParameterType::Bool> {
  bool value;

public:
  void set(snort::Value &val) { value = val.get_bool(); }

  bool get() { return value; }
};

template <> class ParamStorage<ParameterType::Int> {
  int value;

public:
  void set(snort::Value &val) {

    static_assert(sizeof(value) == 4 || sizeof(value) == 8,
                  "Support only implemented for 4 and 8 byte integers");

    if constexpr (sizeof(value) == 4) {
      value = val.get_int32();
    } else if constexpr (sizeof(value) == 8) {
      value = val.get_int64();
    }
  }

  int get() { return value; }
};

template <> class ParamStorage<ParameterType::String> {
  std::string value;

public:
  void set(snort::Value &val) { value = val.get_as_string(); }

  const std::string &get() { return value; }
};
*/
// Simple Type containing class
template <PegType type>
class PegBaseType : public GenericTypeBaseClass {
public:
  static consteval CountType get_type() {
    return static_cast<CountType>(std::to_underlying(type));
  }
};


template <PegType type>
class Type<type> : public PegBaseType<type> {
  
public:
  static consteval CountType get_type() {
    return static_cast<CountType>(std::to_underlying(type));
  }
};


template <>
class Type<PegType::SUM> : public PegBaseType<PegType::SUM> {
  PegCount &count;
public:
  Type(PegCount &count) : count(count) {}
  
  void inc() {
    count++;
  }

  void add(PegCount value) {
    assert(value >= 0);   // Don't use add to subtract
    count += value;
  }
};

template <>
class Type<PegType::MAX> : public PegBaseType<PegType::MAX> {
  PegCount &count;
public:
  Type(PegCount &count) : count(count) {}
  
  void max(PegCount value) {
    if (value > count) {
      count = value;
    }
  }  
};

template <>
class Type<PegType::NOW> : public PegBaseType<PegType::NOW> {
  PegCount &count;
public:
  Type(PegCount &count) : count(count) {}
  
  void set(PegCount value) {
    count = value;
  }  
};


static_assert(TypeConcept<Type<PegType::SUM>>,
              "Type is not compliant with ConceptType");

}; // namespace trout::templates

#endif // #ifndef pegs_peg_types_BA01A782
