#ifndef module_7cd3dce2
#define module_7cd3dce2

////////////////////////////////////////////////////////////////////////
//
// The module wrapper wraps snort::Module, it integrates the pegs and
// settings/module parameter wrappers by supplying common boiler plate
// code
//
////////////////////////////////////////////////////////////////////////

// Snort includes

// System includes
#include <type_traits>

// Global includes

// Local includes
#include "concepts.h"
#include "parameter_concepts.h"
#include "pegs_concepts.h"

// Debug includes

namespace trout::templates {

// Concept for what can be accepted in a parameter declaration
template <class T>
concept ModuleConfigConcept = PegListConcept<T> || ParamListConcept<T> ||
                              NameConcept<T> || HelpTextConcept<T>;

template <ModuleConfigConcept... module_args>
class Module : public snort::Module {

  [[maybe_unused]] static const auto count_of_peg_lists =
      (0 + ... + PegListConcept<module_args>);

  [[maybe_unused]] static const auto count_of_param_lists =
      (0 + ... + ParamListConcept<module_args>);

  [[maybe_unused]] static const auto count_of_names =
      (0 + ... + NameConcept<module_args>);

  [[maybe_unused]] static const auto count_of_help_texts =
      (0 + ... + HelpTextConcept<module_args>);

  // Mandatory fields
  static_assert(count_of_names == 1,
                "You need to supply a name for the module");

  static_assert(count_of_help_texts == 1,
                "You need to supply a help text/description of the module");

  // Optional fields
  static_assert(count_of_peg_lists <= 1,
                "You can't specify more than one peg list for a single module");

  static_assert(
      count_of_param_lists <= 1,
      "You can't specify more than one param list for a single module");

  // Templates for finding specific element type
  template <template <typename> class Predicate, typename... Ts>
  struct FindMatch {
    static_assert(false, "FindMatch couldn't find the type requested");
  };

  template <template <typename> class Predicate, typename T, typename... Rest>
  struct FindMatch<Predicate, T, Rest...>
      : std::conditional_t<Predicate<T>::value, std::type_identity<T>,
                           FindMatch<Predicate, Rest...>> {};

  template <template <typename> class Predicate>
  using FindType = typename FindMatch<Predicate, module_args...>::type;

  // If params are set, use that type, otherwise default to void
  template <bool has_settings> struct SettingsTypeFinder {
    using type = void;
  };

  template <> struct SettingsTypeFinder<true> {
    using type = FindType<CheckIsParamList>;
  };
  using SettingsType = typename SettingsTypeFinder<count_of_param_lists>::type;

protected:
  std::shared_ptr<SettingsType> settings = std::make_shared<SettingsType>();

public:
  // Available constructors are chosen depending on a param list being given as
  // template parameter
  Module()
    requires(count_of_param_lists == 0)
      : snort::Module(get_module_name(), get_module_help()) {}

  Module(const snort::Parameter *parameter, bool is_list = false)
    requires(count_of_param_lists == 0)
      : snort::Module(get_module_name(), get_module_help(), parameter,
                      is_list) {}

  Module()
    requires(count_of_param_lists == 1)
      : snort::Module(get_module_name(), get_module_help(),
                      SettingsType::generate_snort_def()) {}

  // Pegs related functions
  const PegInfo *get_pegs() const override {
    if constexpr (count_of_peg_lists) {
      return FindType<CheckIsPegList>::generate_snort_peg_info_def();
    } else {
      return nullptr;
    }
  }

  PegCount *get_counts() const override {
    if constexpr (count_of_peg_lists) {

      return FindType<CheckIsPegList>::generate_snort_peg_count_def();
    } else {
      return nullptr;
    }
  }

  // Settings related functions
  bool begin(const char *, int, snort::SnortConfig *) override {
    if constexpr (count_of_param_lists) {
      settings = std::make_shared<SettingsType>();
    }

    return true;
  }

  bool end(const char *, int, snort::SnortConfig *) override {
    if constexpr (count_of_param_lists) {
      return settings->end();
    } else {
      return true;
    }
  }

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if constexpr (count_of_param_lists) {
      return settings->set(val.get_name(), val);
    } else {
      return false;
    }
  }

  std::shared_ptr<SettingsType> get_settings() { return settings; }

  static const char *get_module_name() {
    return FindType<CheckIsName>::get_cstring();
  }

  static const char *get_module_help() {
    return FindType<CheckIsHelpText>::get_cstring();
  }
};

} // namespace trout::templates

#endif // #ifndef module_7cd3dce2
