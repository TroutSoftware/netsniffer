#ifndef cache_template_serializer_9E2B7A42
#define cache_template_serializer_9E2B7A42

// Snort includes
// #include <protocols/packet.h>

// System includes
#include <algorithm>
#include <array>
#include <concepts>
#include <memory>
#include <mutex>
#include <type_traits>

// Global includes
#include "../includes/log_framework.h"
#include "../includes/trout_utils.h"

// Local includes
#include "cache_concepts.h"

// Debug includes

namespace trout_netflow2 {

////////////////////////////////////////////////////////////////////////
// Concrete implementaitions
////////////////////////////////////////////////////////////////////////

// Implementation of a MUTEX element, taking a lambda in its definition
template <auto v> class MUTEX : public IsMutex {
public:
  static std::mutex &get_mutex(auto &itr) { return v(itr); }
};
static_assert(ConceptIsMutex<MUTEX<1>>,
              "MUTEX need to comply with ConceptIsMutex");

// Implementation of a DIRTY element, taking a lambda in its definition
template <auto v> class DIRTY : public IsDirty {
public:
  static bool &get_dirty(auto &itr) { return v(itr); }
};
static_assert(ConceptIsDirty<DIRTY<1>>,
              "DIRTY needs to comply with ConceptIsDirty");

// Serializable implementation for service maps (trout specific structure)
// A servicemap is collection of service names and numeric ID's
template <uint16_t fixed_string_size, int key>
class ServiceMapE : public IsStreamable {
  static_assert((fixed_string_size % 4) == 0,
                "For alignment the string size must be a multiplum of 4 bytes");

public:
  consteval static uint16_t field_type_in_h() { return key; }

  consteval static bool is_fixed_size() { return true; }

  consteval static uint16_t get_max_encoded_size() {
    return sizeof(Cache::ServiceMap::ServiceKeyT) + fixed_string_size;
  }

  static uint16_t append_value(std::string &output, auto &itr) {
    // itr->first is the string, itr->second is the key

    // NOTE: If the service key size is changed, ensure we still have alignment
    // of complete entry (i.e. string + key sizes)
    static_assert(sizeof(Cache::ServiceMap::ServiceKeyT) == 4,
                  "Converting to network byte order must fit size of key");
    Cache::ServiceMap::ServiceKeyT nkey = Common::to_network_order(itr->second);

    output.append(
        std::string(reinterpret_cast<const char *>(&nkey), sizeof(nkey)));

    output.append(itr->first.substr(0, fixed_string_size));

    if (fixed_string_size > itr->first.size()) {
      output.append(fixed_string_size - itr->first.size(), '\0');
    }

    return fixed_string_size + sizeof(Cache::ServiceMap::ServiceKeyT);
  }

  static void clear_if_volatile(auto &) {
    // We never clear anything in the service map
  }
};
static_assert(ConceptIsStreamable<ServiceMapE<0, 0>>,
              "ServiceMapE must comply with ConceptIsStreamable");

namespace TH {
// Helper templates to determine specific input types

template <typename T, typename C> static T get_type(T C::*);
template <typename T, typename C> static C get_class(T C::*);

template <typename TA> struct IsStdArray : std::false_type {};
template <typename TA, std::size_t N>
struct IsStdArray<std::array<TA, N>> : std::true_type {
  constexpr const static std::size_t size = N * sizeof(TA);
};

template <typename T> struct Is8bitString : std::false_type {};
static_assert(sizeof(char) == 1, "We only support 8-bit chars");
template <> struct Is8bitString<std::string> : std::true_type {};
template <> struct Is8bitString<std::u8string> : std::true_type {};
}; // namespace TH

// Variable length field (RFC 5101) if max_size == min_size, compatible with RFC
// 3954
template <auto v, int key, uint16_t max_size, uint16_t min_size = 0>
class EVS : public IsStreamable {

  // Definitions to extract types from v
  using T = decltype(TH::get_type(v));
  using C = decltype(TH::get_class(v));

  // Validation we can handle the input
  static_assert(max_size > 0, "Max size can't be 0");

  static_assert(max_size <= 0xFFFF, "Max size can't be over 16-bit");
  static_assert(min_size <= max_size,
                "max_size can't be greater than min_size");
  static_assert(!std::is_integral_v<T> ||
                    (max_size == min_size && sizeof(T) == max_size),
                "We don't support truncation of integers");

  static_assert(
      [] {
        if constexpr (TH::IsStdArray<T>::value) {
          return (max_size == min_size && TH::IsStdArray<T>::size == max_size);
        }
        return true;
      }(),
      "We only support arrays of exact size");

public:
  consteval static uint16_t field_type_in_h() { return key; }

  consteval static bool is_fixed_size() {
    // The max_size == min_size captures std::array, as we have a precondition
    // for it to hold true for std::array
    if constexpr (max_size == min_size) {
      return true;
    } else if constexpr (TH::Is8bitString<T>::value) {
      return false;
    } else {
      static_assert(false, "The type can't be streamed with EVS");
    }
  }

  consteval static uint16_t get_max_encoded_size() {
    if constexpr (is_fixed_size()) {
      return max_size;
    }

    // If we are variable size (ie. not fixed size), we need to add the variable
    // lenght fields to the max size
    if constexpr (max_size <= 255) {
      return max_size + 1;
    }

    static_assert(
        max_size < (0xFFFF - 3),
        "We don't have space for the 3-bit sizing for long variable data");

    return max_size + 3;
  }

  static uint16_t append_value(std::string &output, auto &itr) {
    // We can't have the specific type in the signature as we use concepts for
    // checking, and the concept doesn't know about the type
    static_assert(std::same_as<decltype(itr), Cache::CacheMapType::iterator &>,
                  "We only support Cache::CacheMapType::iterator");

    const C *p;

    if constexpr (std::is_same_v<C, Cache::CacheElement2::ConstValues>) {
      p = &(itr->first);
    } else {
      p = itr->second
              .get(); // second is a shared_ptr to the one we really want to get
    }

    assert(p); // the caller needs to ensure we have valid input

    T value = p->*v;

    if constexpr (TH::IsStdArray<T>::value) {
      static_assert(is_fixed_size(),
                    "Arrays are only implemented for fixed size transfers");

      static_assert(
          sizeof(typename T::value_type) == 1,
          "We don't handle std::arrays not made up of byte sized elements");

      output.append(value.begin(), value.end());
      return value.size();
    } else if constexpr (std::is_integral_v<T>) {
      static_assert(is_fixed_size(),
                    "integers are only implemented for fixed size transfers");

      T nv = Common::to_network_order(value);

      output.append(reinterpret_cast<const char *>(&nv), sizeof(T));

      return sizeof(T);
    } else if constexpr (TH::Is8bitString<T>::value) {
      auto size_to_copy =
          std::min(value.size(), static_cast<T::size_type>(max_size));
      auto actual_length =
          std::max(size_to_copy, static_cast<T::size_type>(min_size));
      auto prefix_size = 0;

      // If variable length, we need to prefix with 1 to 3 length bytes
      if constexpr (!is_fixed_size()) {
        // Note: 0xFF is reserved for long data
        if (actual_length < 0xFF) {
          prefix_size = 1;
          output.push_back(static_cast<char>(actual_length & 0xFF));
        } else {
          output.append({static_cast<char>(0xFF),
                         static_cast<char>((actual_length >> 8) & 0xFF),
                         static_cast<char>(actual_length & 0xFF)});
          prefix_size = 3;
        }
      }

      output.append(reinterpret_cast<const char *>(value.data()), size_to_copy);

      if (size_to_copy >= min_size) {
        return size_to_copy + prefix_size;
      } else {
        output.append(min_size - size_to_copy, '\0');
        return min_size + prefix_size;
      }
    } else {
      static_assert(false, "We don't know how to serialize the argument");
    }
  }

  static void clear_if_volatile(auto &itr) {
    static_assert(std::same_as<decltype(itr), Cache::CacheMapType::iterator &>,
                  "We only support Cache::CacheMapType::iterator");
    // We only clear if volatile
    if constexpr (std::is_same_v<C, Cache::CacheElement2::VolatileValues>) {
      static_assert(std::is_integral_v<T>, "We can only clear numbers");

      itr->second.get()->*v = 0;
    }
  }
};

template <auto v, int key>
using E = EVS<v, key, sizeof(TH::get_type(v)), sizeof(TH::get_type(v))>;

// CVS is same as EVS, except it treats the element as Constant, i.e. it won't
// be cleared after serialization
template <auto v, int key, uint16_t max_size, uint16_t min_size = 0>
class CVS : public EVS<v, key, max_size, min_size> {
public:
  static void clear_if_volatile(auto &) {}
};

template <auto v, int key>
using C = CVS<v, key, sizeof(TH::get_type(v)), sizeof(TH::get_type(v))>;

// Helper function to generate data flow set id's
uint16_t generate_template_data_flow_set_id() {
  static uint16_t next_id = 256;
  assert(next_id <= 65535 && next_id >= 256); // Limits from RFC3954
  return next_id++;
}

// The main engine class, taking the defintion of the content as template
// parameters
template <ConceptNetflowDefinition... list> class NFSerializer {
  // Count some elemement types
  [[maybe_unused]] static const auto count_of_all_elements = sizeof...(list);
  static const auto count_of_dirty_elements = (0 + ... + ConceptIsDirty<list>);
  static const auto count_of_mutex_elements = (0 + ... + ConceptIsMutex<list>);
  static const auto count_of_streamable_elements =
      (0 + ... + ConceptIsStreamable<list>);

  // Check validity of list
  static_assert(count_of_streamable_elements > 0,
                "You need to specify at least one streamable element in the "
                "template list");
  static_assert(count_of_dirty_elements <= 1,
                "You can only have one dirty object in the template list");
  static_assert(count_of_mutex_elements <= 1,
                "You can only have one mutex obejct in the template list");

  // Templates for finding specific element type
  template <template <typename> class Predicate, typename... Ts>
  struct FindMatch;

  template <template <typename> class Predicate, typename T, typename... Rest>
  struct FindMatch<Predicate, T, Rest...>
      : std::conditional_t<Predicate<T>::value, std::type_identity<T>,
                           FindMatch<Predicate, Rest...>> {};

  template <template <typename> class Predicate>
  using FindType = typename FindMatch<Predicate, list...>::type;

  // Template that calls f (e.g. a lambda) on all types in the template argument
  // list
  template <class T> static constexpr void call_on_all(T &&f) {
    // Fold expression
    (std::forward<T>(f).template operator()<list>(), ...);
  }

  // Template that calls f (e.g. a lambda) on all types in the template argument
  // list and sums their return values
  template <class T> static constexpr auto sum_of_all(T &&f) {
    // Fold expression
    if constexpr (sizeof...(list) > 0) {
      return (... + std::forward<T>(f).template operator()<list>());
    } else {
      return 0;
    }
  }

  static uint16_t get_id() {
    static uint16_t id = generate_template_data_flow_set_id();
    return id;
  }

  template <std::integral T> static void appendX(std::string &s, T value) {
    T nv = Common::to_network_order(value);
    s.append(std::string(reinterpret_cast<const char *>(&nv), sizeof(nv)));
  }

  static void append16(std::string &s, uint16_t value) {
    appendX<uint16_t>(s, value);
  }

  static void append32(std::string &s, uint32_t value) {
    appendX<uint32_t>(s, value);
  }

  static void append_template_list(std::string &s) {
    auto lambda = [&s]<class T>() {
      if constexpr (ConceptIsStreamable<T>) {
        append16(s, T::field_type_in_h());

        if constexpr (T::is_fixed_size()) {
          append16(s, T::get_max_encoded_size());
        } else {
          append16(s, 0xFFFF); // -> Size stored in value field
        }
      }
    };

    call_on_all(lambda);
  }

  consteval static uint16_t get_packet_header_length() {
    return 40; // See RFC3954
  };

  consteval static uint16_t get_flow_set_header_length() {
    return 4; // As per RFC3954
  };

  consteval static bool has_mutex_object() { return count_of_mutex_elements; }
  consteval static bool has_dirty_object() { return count_of_dirty_elements; }

  // Returns the maximum size a data packet can have
  consteval static uint16_t max_sum_value_lengths() {
    auto lambda = []<class T>() -> size_t {
      if constexpr (ConceptIsStreamableVarSize<T>) {
        return T::get_max_encoded_size();
      }
      return 0;
    };

    // The generated output needs to be 4-byte alligned, so correct the
    // calculation
    constexpr size_t sum =
        sum_of_all(lambda) + ((4 - (sum_of_all(lambda) % 4)) % 4);

    // We can't pack it in a header, unless the header + max size fits in 16-bit
    // The (-3) is to ensure the result can be alligned to a 32-bit boundary
    static_assert((sum + get_flow_set_header_length()) <= (0xFFFF - 3),
                  "Worst case data too big to fit in a Netflow package");

    return static_cast<uint16_t>(sum);
  }

  static void generate_flow_set_header(std::string &s, uint16_t size_of_data) {
    // Padding needs to happen outside of this function
    assert(size_of_data % 4 == 0);

    // We only have 16-bits for the size
    assert((size_of_data + get_flow_set_header_length()) < 0xFFFF);

    append16(s, get_id());
    append16(s, get_flow_set_header_length() + size_of_data);
  }

  static std::string generate_flow_set_header(uint16_t size_of_data) {
    std::string s;
    s.reserve(get_flow_set_header_length());
    generate_flow_set_header(s, size_of_data);

    return s;
  }

  static void serialize(std::string &s, auto &itr) {
    // Increase size of string to fit output
    s.reserve(s.size() + max_sum_value_lengths());
    auto lambda = [&s, &itr]<class T>() {
      if constexpr (ConceptIsStreamable<T>) {
        T::append_value(s, itr);
      }
    };

    call_on_all(lambda);
  }

  static void clear_volatile(auto &itr) {
    auto lambda = [&itr]<class T> {
      if constexpr (std::is_base_of_v<IsStreamable, T>) {
        T::clear_if_volatile(itr);
      }
    };

    call_on_all(lambda);
  }

public:
  static std::string generate_packet_header(uint32_t now_in_s,
                                            uint32_t sequence_number,
                                            uint32_t source_id,
                                            uint16_t flow_set_count) {
    std::string s;
    s.reserve(get_packet_header_length());
    append16(s, 9);              // The version of binary netflow we adhere to
    append16(s, flow_set_count); // Number of flow sets in the packet
    append32(s, 0);              // TODO: add up time (seconds since boot)
    append32(s, now_in_s);       // Unix time
    append32(s, sequence_number);
    append32(s, source_id); // Unique number identifying me

    assert(s.length() != get_packet_header_length());

    return s;
  }

  static std::string generate_template(uint32_t flow_set_id) {
    assert(flow_set_id == 0); // We only support 0 for now (Template FlowSet)
    std::string s;
    const uint16_t length =
        4 * count_of_streamable_elements + 8 /* Header size */;
    s.reserve(length);

    // See RFC3954 for format
    append16(s, flow_set_id); // FlowSet ID 0 = Template format
    append16(s, length);      // Total length of package
    append16(s, get_id());
    append16(s, count_of_streamable_elements);

    append_template_list(s); // Add the template data from each element

    return s;
  }

  // Returns number of flow sets written
  template <class C> static uint32_t dump(LioLi::Tree &tree, C &container) {
    std::string out_buffer;
    out_buffer.reserve(
        UINT16_MAX); // Note, a netflow FlowSet is limited to 64Kb

    const size_t data_size = UINT16_MAX - get_flow_set_header_length();

    static_assert(data_size >= max_sum_value_lengths(),
                  "We don't have enough space with 16-bit sizes to serialize");

    uint32_t flowsets_written = 0;

    auto itr = container.begin();

    while (itr != container.end()) {
      // Serialize what the itr points to:
      bool isDirty = true; // We assume dirty unless we know it isn't

      // We intentionally do manually locking and unlocking due to lifetime
      // contraints
      if constexpr (has_mutex_object()) {
        FindType<CheckIsMutex>::get_mutex(itr).lock();
      }

      if constexpr (has_dirty_object()) {
        isDirty = FindType<CheckIsDirty>::get_dirty(itr);
        FindType<CheckIsDirty>::get_dirty(itr) = false;
      }

      if (isDirty) {
        serialize(out_buffer, itr);
        clear_volatile(itr);
      }

      if constexpr (has_mutex_object()) {
        FindType<CheckIsMutex>::get_mutex(itr).unlock();
      }

      // We increment itr here, so we know if we are about to be at the end and
      // should flush
      itr++;

      // If we don't have enough space to add more or have come to the end, then
      // send what we have if any
      if ((data_size - out_buffer.size() < max_sum_value_lengths() ||
           itr == container.end()) &&
          out_buffer.size() > 0) {

        // Check if we need to pad what we have
        size_t padding = (4 - (out_buffer.size() % 4)) % 4;

        if (padding) {
          out_buffer.append(padding, '\0');
        }

        tree << (LioLi::Tree("DataFlowSet")
                 << generate_flow_set_header(
                        out_buffer.size()) // TODO: Check if std::move is needed
                 << out_buffer);

        // Count the flowset
        flowsets_written++;

        // Break if we have more flowsets than what fits, the rest will be
        // written in the next iteration
        if (flowsets_written == UINT32_MAX) {
          break;
        }

        // Reset the out_buffer
        out_buffer.clear();
      }
    }; // while (itr != container.end())

    return flowsets_written;
  }
};

} // namespace trout_netflow2

#endif // cache_template_serializer_9E2B7A42
