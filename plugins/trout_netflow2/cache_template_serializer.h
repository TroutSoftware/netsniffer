#ifndef cache_template_serializer_9E2B7A42
#define cache_template_serializer_9E2B7A42

// Snort includes
// #include <protocols/packet.h>

// System includes
#include <array>
#include <memory>
#include <mutex>
#include <type_traits>

// Global includes
#include <log_framework.h>

// Local includes
#include "trout_utils.h"

// Debug includes

namespace trout_netflow2 {

// Classes inheriting from this are streamable/serializable
// A streamable class must have at least these functions:
//   constexpr static uint16_t field_type_in_h()
//     -- Returns the type of the field in the RFC rfc3954 sense
//   constexpr static uint16_t size_in_hbytes()
//     -- Size of the serialized chunk
//   static void append_value(std::string &output, <iterator> &itr)
//     -- Function taking an iterator and serializing what it references to a
//     bytestream
//   static void clear_if_volatile(<iterator> &)
//     -- Function that clears variables (if needed) after serialization
class IsStreamable {};

// Classes inheriting from this is the mutex
// A mutex class, is one that lets the framework get the mutex of a specific
// element. The mutex will be taken by the framework before append_value and
// clear_if_volatile are called on the streamable class A mutex class must at
// last contain this function:
//   static std::mutex &get_mutex(<iterator> &itr)
//     -- returns a referenct to a standard mutex object for object the iterator
//     points to
class IsMutex {};

// Implementation of a MUTEX element, taking a lambda in its definition
template <auto v> class MUTEX : public IsMutex {
public:
  static std::mutex &get_mutex(auto &itr) { return v(itr); }
};

// Class inheriting from this is a dirty flag
// A dirty class, is one that lets the framework check the dirty state of a
// specific element If a dirty definition is pressent, it won't be serialized
// unless the dirty state is true A dirty calss must at least contain this
// function:
//   static bool &get_dirty(auto &itr)
//     -- returns true if the iterator points to a dirty value, false otherwise
class IsDirty {};

// Implementation of a DIRTY element, taking a lambda in its definition
template <auto v> class DIRTY : public IsDirty {
public:
  static bool &get_dirty(auto &itr) { return v(itr); }
};

// Serializable implementation for service maps (trout specific structure)
// A servicemap is collection of service names and numeric ID's
template <uint16_t fixed_string_size, int key>
class ServiceMapE : public IsStreamable {
  static_assert((fixed_string_size % 4) == 0,
                "For alignment the string size must be a multiplum of 4 bytes");

public:
  consteval static uint16_t field_type_in_h() { return key; }

  consteval static uint16_t size_in_hbytes() {
    return sizeof(Cache::ServiceMap::ServiceKeyT) + fixed_string_size;
  }

  static void append_value(std::string &output,
                           Cache::ServiceMap::ServiceMapT::iterator &itr) {
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
  }

  static void clear_if_volatile(auto &) {
    // We never clear anything in the service map
  }
};

// Template used to declare data entries for the binary netflow format
// fixed_size denotes the size for the field in the binary data, even
// the member (v) has a different size (Must be 0, 1, 2, 4 or 8, where 0
// means use the real size of v)
template <auto v, int key, uint16_t fixed_size = 0>
class E : public IsStreamable {
protected:
  static_assert(fixed_size == 0, "Fixed size not implemented yet");

  // Definitions to extract types from v
  template <typename T, typename C> static T get_type(T C::*);
  template <typename T, typename C> static C get_class(T C::*);

  using T = decltype(get_type(v));
  using C = decltype(get_class(v));

  // Helper templates to determine specific input types
  template <typename TA> struct IsStdArray : std::false_type {};
  template <typename TA, std::size_t N>
  struct IsStdArray<std::array<TA, N>> : std::true_type {
    constexpr const static std::size_t size = N * sizeof(TA);
  };

public:
  consteval static uint16_t field_type_in_h() { return key; }

  consteval static uint16_t size_in_hbytes() {
    if constexpr (IsStdArray<T>::value) {
      static_assert(fixed_size == 0); // We can not change size of arrays
      return IsStdArray<T>::size;
    } else if constexpr (fixed_size != 0) {
      return fixed_size;
    } else {
      return sizeof(T);
    }
  }

  static void append_value(std::string &output,
                           Cache::CacheMapType::iterator &itr) {
    const C *p;

    if constexpr (std::is_same_v<C, Cache::CacheElement2::ConstValues>) {
      p = &(itr->first);
    } else {
      p = itr->second
              .get(); // second is a shared_ptr to the one we really want to get
    }

    assert(p); // the caller needs to ensure we have valid input

    T value = p->*v;

    if constexpr (IsStdArray<T>::value) {
      static_assert(
          sizeof(typename T::value_type) == 1,
          "We don't handle std::arrays not made up of byte sized elements");

      output.append(value.begin(), value.end());
    } else if constexpr (std::is_integral_v<T>) {
      // Not an array, we just convert blindly to network format
      T nv = Common::to_network_order(value);

      output.append(reinterpret_cast<const char *>(&nv), sizeof(T));
    } else {
      static_assert(false, "I don't know how to serialize the argument");
    }
  }

  static void clear_if_volatile(Cache::CacheMapType::iterator &itr) {
    // We only clear if volatile
    if constexpr (std::is_same_v<C, Cache::CacheElement2::VolatileValues>) {
      static_assert(!IsStdArray<T>::value and !std::is_array_v<T>,
                    "Arrays not implemented in volatile part");

      itr->second.get()->*v = 0;
    }
  }
};

// C is same as E, except it treats the element as Constant, i.e. it won't be
// cleared after serialization
template <auto v, int key, uint16_t fixed_size = 0>
class C : public E<v, key, fixed_size> {
public:
  static void clear_if_volatile(Cache::CacheMapType::iterator &) {}
};

// Variable length field (RFC 5101)
template <auto v, int key, uint16_t max_size, uint16_t min_size = 1>
class EVS : public IsStreamable {
  // Definitions to extract types from v
  template <typename T, typename C> static T get_type(T C::*);
  template <typename T, typename C> static C get_class(T C::*);

  using T = decltype(get_type(v));
  using C = decltype(get_class(v));

  // Helper templates to determine specific input types
  template <typename TA> struct IsStdArray : std::false_type {};
  template <typename TA, std::size_t N>
  struct IsStdArray<std::array<TA, N>> : std::true_type {
    constexpr const static std::size_t size = N * sizeof(TA);
  };

  template <typename T> struct Is8bitString : std::false_type {};
  static_assert(sizeof(char) == 1, "We only support 8-bit chars");
  template <> struct Is8bitString<std::string> : std::true_type {};
  template <> struct Is8bitString<std::u8string> : std::true_type {};

  // Validation we can handle the input
  static_assert(max_size > 0, "Max size can't be 0");
  static_assert(max_size <= 0xFFFF, "Max size can't be over 16-bit");
  static_assert(min_size <= max_size,
                "max_size can't be greater than min_size");
  static_assert(std::is_integral_v<T> && max_size != min_size &&
                    sizeof(T) != max_size,
                "We don't support truncation of integers");
  static_assert(IsStdArray<T>::value && max_size != min_size &&
                    IsStdArray<T>::size != max_size,
                "We only support arrays of exact size");

public:
  consteval static uint16_t field_type_in_h() { return key; }

  consteval static bool is_fixed_size() {
    // The max_size == min_size captures std::array, as we have a precondition
    // for it to hold true for std::array
    if constexpr (max_size == min_size) {
      return true;
    } else if constexpr (Is8bitString<T>::value) {
      return false;
    } else {
      static_assert(false, "The type can't be streamed with EVS");
    }
  }

  consteval static uint16_t get_max_size() { return max_size; }

  /*
    consteval static uint16_t get_size_in_bytes() {
      if constexpr (isFixedSize()) {
        return max_size;
      } else {
        static_assert(false, "size_in_bytes can't be called a variable lenght
    data");
      }
    }
  */

  static uint16_t append_value(std::string &output,
                               Cache::CacheMapType::iterator &itr) {
    const C *p;

    if constexpr (std::is_same_v<C, Cache::CacheElement2::ConstValues>) {
      p = &(itr->first);
    } else {
      p = itr->second
              .get(); // second is a shared_ptr to the one we really want to get
    }

    assert(p); // the caller needs to ensure we have valid input

    T value = p->*v;

    if constexpr (IsStdArray<T>::value) {
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
    } else if constexpr (Is8bitString<T>::value) {
      auto size_to_copy = std::min(value.size(), max_size);
      auto actual_length = std::max(size_to_copy, min_size);
      auto prefix_size = 0;

      // If variable length, we need to prefix with 1 to 3 length bytes
      if constexpr (!is_fixed_size()) {
        // Note: 0xFF is reserved for long data
        if (actual_length < 0xFF) {
          prefix_size = 1;
          output.push_back(static_cast<char>(actual_length && 0xFF));
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
};

// Helper function to generate data flow set id's
uint16_t generate_template_data_flow_set_id() {
  static uint16_t next_id = 256;
  assert(next_id <= 65535 && next_id >= 256); // Limits from RFC3954
  return next_id++;
}

// The main engine class, taking the defintion of the content as template
// parameters
template <class... list> class NFSerializer {
  static_assert(sizeof...(list) > 0,
                "You need to specify at least one element (E template)");
  static uint16_t get_id() {
    static uint16_t id = generate_template_data_flow_set_id();
    return id;
  }

  // Converts value to network byte order and appends it to the string
  /*
    static void append16(std::string &s, uint16_t value) {
      uint16_t nv = Common::to_network_order(value);
      s.append(std::string(reinterpret_cast<const char *>(&nv), sizeof(nv)));
    }

    static void append32(std::string &s, uint32_t value) {
      uint32_t nv = Common::to_network_order(value);
      s.append(std::string(reinterpret_cast<const char *>(&nv), sizeof(nv)));
    }
  */

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

  template <class T, class... ttypes>
  static void append_template_list(std::string &s) {
    if constexpr (std::is_base_of_v<IsStreamable, T>) {
      append16(s, T::field_type_in_h());

      // A temporary trick while we both have E and EVS
      constexpr bool is_fixed_size = []<typename U = T>() consteval {
        if constexpr (requires {
                        { U::is_fixed_size() } -> std::same_as<bool>;
                      }) {
          return U::is_fixed_size();
        } else {
          return true;
        }
      }();

      if constexpr (is_fixed_size) {
        append16(s, T::size_in_hbytes());
      } else {
        append16(s, 0xFFFF); // -> Size stored in value field
      }
    }
    if constexpr (sizeof...(ttypes) != 0) {
      append_template_list<ttypes...>(s);
    }
  }

  template <class T, class... ttypes> consteval static uint16_t value_length() {
    uint16_t size_of_me = 0;
    uint16_t size_of_rest = 0;

    if constexpr (std::is_base_of_v<IsStreamable, T>) {
      size_of_me = T::size_in_hbytes();
    }

    if constexpr (sizeof...(ttypes) != 0) {
      size_of_rest = value_length<ttypes...>();
    }

    return size_of_me + size_of_rest;
  }

  template <class T, class... ttypes>
  static void build_data(std::string &s, auto &itr) {
    if constexpr (std::is_base_of_v<IsStreamable, T>) {
      auto bs = s.size();
      T::append_value(s, itr);
      assert(s.size() - bs ==
             T::size_in_hbytes()); // Check the expected size was added
    }

    if constexpr (sizeof...(ttypes) != 0) {
      build_data<ttypes...>(s, itr);
    }
  }

  template <class T, class... ttypes>
  static void clear_volatile_data(auto &itr) {
    if constexpr (std::is_base_of_v<IsStreamable, T>) {
      T::clear_if_volatile(itr);
    }
    if constexpr (sizeof...(ttypes) != 0) {
      clear_volatile_data<ttypes...>(itr);
    }
  }

  template <class T, class... ttypes>
  consteval static uint16_t count_streamable() {
    uint16_t sum = 0;
    if constexpr (std::is_base_of_v<IsStreamable, T>) {
      sum = 1;
    }
    if constexpr (sizeof...(ttypes) != 0) {
      sum += count_streamable<ttypes...>();
    }
    return sum;
  }

  // TODO: Merge the x_mutex_x and x_dirty_x functions to common base
  template <class T, class... ttypes>
  consteval static void ensure_no_mutex_object() {
    static_assert(!std::is_base_of_v<IsMutex, T>,
                  "You can only have one MUTEX entry in the definition");
    if constexpr (sizeof...(ttypes) != 0) {
      ensure_no_mutex_object<ttypes...>();
    }
  }

  template <class T, class... ttypes> consteval static bool has_mutex_object() {
    if constexpr (std::is_base_of_v<IsMutex, T>) {
      if constexpr (sizeof...(ttypes) != 0) {
        ensure_no_mutex_object<ttypes...>();
      }
      return true;
    }
    if constexpr (sizeof...(ttypes) != 0) {
      return has_mutex_object<ttypes...>();
    } else {
      return false;
    }
  }

  template <class T, class... ttypes>
  static std::mutex &get_mutex_object(auto &itr) {
    if constexpr (std::is_base_of_v<IsMutex, T>) {
      return T::get_mutex(itr);
    } else {
      static_assert(sizeof...(ttypes) != 0, "Missing MUTEX entry");
      return get_mutex_object<ttypes...>(itr);
    }
  }

  template <class T, class... ttypes>
  consteval static void ensure_no_dirty_object() {
    static_assert(!std::is_base_of_v<IsDirty, T>,
                  "You can only have one DIRTY entry in the definition");
    if constexpr (sizeof...(ttypes) != 0) {
      ensure_no_dirty_object<ttypes...>();
    }
  }

  template <class T, class... ttypes> consteval static bool has_dirty_object() {
    if constexpr (std::is_base_of_v<IsDirty, T>) {
      if constexpr (sizeof...(ttypes) != 0) {
        ensure_no_dirty_object<ttypes...>();
      }
      return true;
    }
    if constexpr (sizeof...(ttypes) != 0) {
      return has_dirty_object<ttypes...>();
    } else {
      return false;
    }
  }

  template <class T, class... ttypes> static bool &get_dirty_object(auto &itr) {
    static_assert(has_dirty_object<T, ttypes...>(), "Missing DIRTY entry");

    if constexpr (std::is_base_of_v<IsDirty, T>) {
      return T::get_dirty(itr);
    } else {
      return get_dirty_object<ttypes...>(itr);
    }
  }

public:
  consteval static uint16_t count_elements() { return sizeof...(list); }

  consteval static uint16_t sum_value_lengths() {
    return value_length<list...>();
  }

  consteval static uint16_t get_packet_header_length() {
    return 40; // See RFC3954
  };

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
        4 * count_streamable<list...>() + 8 /* Header size */;
    s.reserve(length);

    // See RFC3954 for format
    append16(s, flow_set_id); // FlowSet ID 0 = Template format
    append16(s, length);      // Total length of package
    append16(s, get_id());
    append16(s, count_streamable<list...>());

    append_template_list<list...>(s); // Add the template data from each element

    return s;
  }

  static void generate_flow_set_header(std::string &s, uint16_t no_of_records) {
    append16(s, get_id());
    append16(s, get_flow_set_header_length() +
                    (no_of_records *
                     sum_value_lengths())); // Total length of package
  }

  consteval static uint16_t get_flow_set_header_length() {
    return 4; // As per RFC3954
  };

  static std::string generate_flow_set_header(uint16_t no_of_records) {
    std::string s;
    s.reserve(get_flow_set_header_length());
    generate_flow_set_header(s, no_of_records);

    return s;
  }

  static void serialize(std::string &s, auto &itr) {
    build_data<list...>(s, itr);
  }

  static std::string serialize(auto &itr) {
    std::string s;
    s.reserve(sum_value_lengths()); // Reserve space for the entry
    serialize(s, itr);
    return s;
  }

  static void clear_volatile(auto &itr) { clear_volatile_data<list...>(itr); }

  template <class C> static uint32_t dump(LioLi::Tree &tree, C &container) {
    // Find max number of Flow Records in each FlowSet
    constexpr const static uint16_t max_to_send =
        (UINT16_MAX - get_flow_set_header_length()) / sum_value_lengths();

    static_assert(max_to_send >= 1, "Data too big for dumping");

    uint16_t record_counter = 0;  // How many records have we serialized so far
    uint16_t flowset_counter = 0; // How many flow sets we have serizlized

    std::string out_buffer;
    out_buffer.reserve(
        UINT16_MAX); // Note, a netflow FlowSet is limited to 64Kb

    // Iterate over the container
    auto itr = container.begin();

    while (itr != container.end()) {

      // We intentionally do manually locking and unlocking due to lifetime
      // contraints
      if constexpr (has_mutex_object<list...>()) {
        get_mutex_object<list...>(itr).lock();
      }

      bool isDirty = true; // We assume dirty unless we know it isn't

      if constexpr (has_dirty_object<list...>()) {
        isDirty = get_dirty_object<list...>(itr);
        get_dirty_object<list...>(itr) = false;
      }

      if (isDirty) {
        serialize(out_buffer, itr);
        clear_volatile(itr);
        record_counter++;
      }

      if constexpr (has_mutex_object<list...>()) {
        get_mutex_object<list...>(itr).unlock();
      }

      itr++;
      if (record_counter >= max_to_send ||
          (itr == container.end() && record_counter > 0)) {
        tree << (LioLi::Tree("DataFlowSet")
                 << generate_flow_set_header(
                        record_counter) // TODO: Check if std::move is needed
                 << out_buffer);
        // Reset the out_buffer
        out_buffer.clear();
        out_buffer.reserve(UINT16_MAX);
        // We start over on the counter
        record_counter = 0;
        flowset_counter++;
      }
    }

    return flowset_counter;
  }
};

} // namespace trout_netflow2

#endif // cache_template_serializer_9E2B7A42
