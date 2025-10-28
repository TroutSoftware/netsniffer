
// Snort includes
#include <protocols/eth.h>

// System includes
#include <arpa/inet.h>
#include <chrono>
#include <endian.h>
#include <string>
#include <type_traits>

// Global includes
#include "testable_time.h"

// Local includes
#include "cache.h"
#include "pegs.h"
#include "settings.h"

// Debug includes

namespace trout_netflow2 {

Cache::Cache(std::shared_ptr<Settings> settings) : settings(settings) {
  assert(settings);

  start_worker();
}

Cache::~Cache() {
  stop_worker();
  dump();
}

std::shared_ptr<Cache> Cache::create_cache(std::shared_ptr<Settings> settings) {
  std::shared_ptr<Cache> cache(new Cache(settings));

  return cache;
}

Cache::ServiceMap::ServiceMap() { get_add("[unknown]"); }

Cache::ServiceMap::ServiceKeyT
Cache::ServiceMap::get_add(const char *service_name) {
  std::scoped_lock lock(mutex);
  return (service_map.emplace(service_name, service_map.size()).first)->second;
}

Cache::ServiceMap::ServiceKeyT
Cache::ServiceMap::get_add(const std::string &service_name) {
  return get_add(service_name.c_str());
}

std::size_t Cache::ServiceMap::size() { return service_map.size() - 1; }

bool Cache::ServiceMap::is_fully_flushed() {
  std::scoped_lock lock(mutex);

  return service_map.size() == size_at_last_dump;
}

bool Cache::CacheElement2::ConstValuesComp::operator()(
    const Cache::CacheElement2::ConstValues &lhs,
    const Cache::CacheElement2::ConstValues &rhs) const {
  return (lhs.ipv4_src_addr <=> rhs.ipv4_src_addr) < 0 ||
         ((lhs.ipv4_src_addr <=> rhs.ipv4_src_addr) == 0 &&
          ((lhs.ipv4_dst_addr <=> rhs.ipv4_dst_addr) < 0 ||
           ((lhs.ipv4_dst_addr <=> rhs.ipv4_dst_addr) == 0 &&
            (lhs.l4_src_port < rhs.l4_src_port ||
             (lhs.l4_src_port == rhs.l4_src_port &&
              (lhs.l4_dst_port < rhs.l4_dst_port ||
               (lhs.l4_dst_port == rhs.l4_dst_port &&
                ((lhs.src_mac <=> rhs.src_mac) < 0 ||
                 ((lhs.src_mac <=> rhs.src_mac) == 0 &&
                  ((lhs.dst_mac <=> rhs.dst_mac) < 0))))))))));
};

Cache::Handle::Handle(std::shared_ptr<Cache> cache,
                      std::shared_ptr<CacheElement2::VolatileValues> data)
    : data(data), cache(cache) {
  assert(cache);
  assert(data);
}

void Cache::Handle::add_sizes(snort::Packet *p) {
  assert(p);
  std::scoped_lock lock(data->mutex);
  if (p->is_from_client()) {
    data->in_pkts++;
    data->in_bytes += p->pktlen;
  } else {
    data->out_pkts++;
    data->out_bytes += p->pktlen;
  }

  data->dirty = true;

  Pegs::s_peg_counts.total_bytes += p->pktlen;
}

void Cache::Handle::add_service(const char *s) {
  assert(data);
  ServiceMap::ServiceKeyT key = cache->service_map.get_add(s);

  Pegs::s_peg_counts.different_services = cache->service_map.size();

  std::scoped_lock lock(data->mutex);

  if (data->service_key != 0 && data->service_key != key) {
    // Count if the service name changed from a different name
    Pegs::s_peg_counts.service_change++;
  }

  data->service_key = key;
  data->dirty = true;
}

void Cache::add(snort::Packet *p) { add_to_cache(p); }

std::unique_ptr<Cache::Handle> Cache::create(snort::Packet *p) {
  return std::unique_ptr<Handle>(
      new Handle(shared_from_this(), add_to_cache(p)));
}

std::shared_ptr<Cache::CacheElement2::VolatileValues>
Cache::add_to_cache(snort::Packet *p) {
  CacheElement2::ConstValues key;

  const snort::eth::EtherHdr *eh =
      ((p->proto_bits & PROTO_BIT__ETH) ? snort::layer::get_eth_layer(p)
                                        : nullptr);

  if (eh) {
    key.src_mac = std::to_array(eh->ether_src);
    key.dst_mac = std::to_array(eh->ether_dst);
  }

  if (p->has_ip()) {
    if (p->ptrs.ip_api.get_src()->is_ip4()) {
      *reinterpret_cast<uint32_t *>(key.ipv4_src_addr.data()) =
          p->ptrs.ip_api.get_src()->get_ip4_value();
    } else {
      // TODO: Handle IPv6 for src, for now just return dummy element
      return std::make_shared<CacheElement2::VolatileValues>();
    }
    if (p->ptrs.ip_api.get_dst()->is_ip4()) {
      *reinterpret_cast<uint32_t *>(key.ipv4_dst_addr.data()) =
          p->ptrs.ip_api.get_dst()->get_ip4_value();
    } else {
      // TODO: Handle IPv6 for dst, for now just return dummy element
      return std::make_shared<CacheElement2::VolatileValues>();
    }

    if (p->is_tcp() || p->is_udp()) {
      key.l4_src_port = p->ptrs.sp;
      key.l4_dst_port = p->ptrs.dp;
    }
  }

  // We don't need the lock until this point
  std::scoped_lock cache_lock(mutex);

  auto itr = ((settings->get_max_cache_size() <= cache.size())
                  ? cache.find(key)
                  : cache.try_emplace(key, nullptr).first);

  // Check if we are getting close to the max
  if (settings->get_max_cache_size() < (cache.size() + (cache.size() >> 3))) {
    kick_worker(); // Will start the process of flushing the cache
  }

  if (itr == cache.end()) {
    Pegs::s_peg_counts.overflow++;

    // Remove a random element, so you can't "hide" in a deterministic way by
    // creating a lot of connections
    int index = random.random(0, cache.size());

    if (!overflow_element) {
      overflow_element = std::make_shared<CacheElement2::VolatileValues>();
    }

    // TODO: Look at this algorithm
    for (auto r = cache.begin(); r != cache.end(); r++) {
      if (index--)
        continue;

      overflow_element->in_pkts += r->second->in_pkts;
      overflow_element->in_bytes += r->second->in_bytes;
      overflow_element->out_pkts += r->second->out_pkts;
      overflow_element->out_bytes += r->second->out_bytes;

      cache.erase(r);
      break;
    }

    itr = cache.try_emplace(key, nullptr).first;
  }

  std::shared_ptr<CacheElement2::VolatileValues> data;

  if (!itr->second) {
    itr->second = std::make_shared<CacheElement2::VolatileValues>();
    data = itr->second;
  } else { // variable part already exists
    data = itr->second;
  }

  std::scoped_lock value_lock(data->mutex);

  if (p->is_from_client()) {
    data->in_pkts++;
    data->in_bytes += p->pktlen;
  } else {
    data->out_pkts++;
    data->out_bytes += p->pktlen;
  }

  // TODO: Figure out if this is ever relevant, or the service is always given
  // through the event system too
  if (p->flow && p->flow->service) {
    auto key = service_map.get_add(p->flow->service);
    Pegs::s_peg_counts.different_services = service_map.size();
    if (data->service_key != 0 && data->service_key != key) {
      // Count if the service name changed from a different name
      Pegs::s_peg_counts.service_change++;
    }
    data->service_key = key;
  }

  data->dirty = true;

  return data;
}

// Classes inheriting from this are streamable
class IsStreamable {};

// Class inheriting from this is the mutex
class IsMutex {};

template <auto v> class MUTEX : public IsMutex {
public:
  static std::mutex &get_mutex(auto &itr) { return v(itr); }
};

// Class inheriting from this is a dirty flag
class IsDirty {};

template <auto v> class DIRTY : public IsDirty {
public:
  static bool &get_dirty(auto &itr) { return v(itr); }
};

template <uint16_t fixed_string_size, int key>
class ServiceMapE : public IsStreamable {
  static_assert((fixed_string_size % 4) == 0,
                "For alignment the string size must be a multiplum of 4 bytes");

public:
  constexpr static uint16_t field_type_in_h() { return key; }

  constexpr static uint16_t size_in_hbytes() {
    return sizeof(Cache::ServiceMap::ServiceKeyT) + fixed_string_size;
  }

  constexpr static void
  append_value(std::string &output,
               Cache::ServiceMap::ServiceMapT::iterator &itr) {
    // itr->first is the string, itr->second is the key

    // NOTE: If the service key size is changed, ensure we still have alignment
    // of complete entry (i.e. string + key sizes)
    static_assert(sizeof(Cache::ServiceMap::ServiceKeyT) == 4,
                  "Converting to network byte order must fit size of key");
    Cache::ServiceMap::ServiceKeyT nkey = htonl(itr->second);

    output.append(
        std::string(reinterpret_cast<const char *>(&nkey), sizeof(nkey)));

    output.append(itr->first.substr(0, fixed_string_size));

    if (fixed_string_size > itr->first.size()) {
      output.append(fixed_string_size - itr->first.size(), '\0');
    }
  }

  constexpr static void clear_if_volatile(auto &) {
    // We never clear anything in the service map
  }
};

// Template used to declare data entries for the binary netflow format
// fixed_size denotes the size for the field in the binary data, even
// the member (v) has a different size (Must be 0, 1, 2, 4 or 8, where 0
// means use the real size of v)
template <auto v, int key, uint16_t fixed_size = 0>
class E : public IsStreamable {
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
  constexpr static uint16_t field_type_in_h() { return key; }
  //  constexpr static uint16_t field_type_in_n() const {return htons(key);}

  constexpr static uint16_t size_in_hbytes() {
    if constexpr (IsStdArray<T>::value) {
      static_assert(fixed_size == 0); // We can not change size of arrays
      return IsStdArray<T>::size;
    } else if constexpr (fixed_size != 0) {
      return fixed_size;
    } else {
      return sizeof(T);
    }
  }
  // constexpr uint16_t size_in_nbytes() const {return htons(size_in_hbytes());}

  constexpr static void append_value(std::string &output,
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
    } else {
      // Not an array, we just convert blindly to network format
      T nv;
      if constexpr (sizeof(T) == 1) {
        nv = value;
      } else if constexpr (sizeof(T) == 2) {
        nv = htons(value);
      } else if constexpr (sizeof(T) == 4) {
        nv = htonl(value);
      } else if constexpr (sizeof(T) == 8) {
        nv = htobe64(value); // Using unix converter as normal htonX doesn't
                             // support 64-bit
      } else {
        static_assert(false, "We do not support the given length of field");
      }

      output.append(
          std::string(reinterpret_cast<const char *>(&nv), sizeof(T)));
    }
  }

  constexpr static void clear_if_volatile(Cache::CacheMapType::iterator &itr) {
    // We only clear if volatile
    if constexpr (std::is_same_v<C, Cache::CacheElement2::VolatileValues>) {
      static_assert(!IsStdArray<T>::value and !std::is_array_v<T>,
                    "Arrays not implemented in volatile part");

      itr->second.get()->*v = 0;
    }
  }
};

// C is same as E, except it treats the element as Constant, i.e. it won't be
// cleared
template <auto v, int key, uint16_t fixed_size = 0>
class C : public E<v, key, fixed_size> {
public:
  constexpr static void clear_if_volatile(Cache::CacheMapType::iterator &) {}
};

// Helper function
uint16_t generate_template_data_flow_set_id() {
  static uint16_t next_id = 256;
  assert(next_id <= 65535 && next_id >= 256); // Limits from RFC3954
  return next_id++;
}

// Class that contains the definition of a FlowSet
template <class... list> class NFSerializer {
  static_assert(sizeof...(list) > 0,
                "You need to specify at least one element (E template)");
  constexpr static uint16_t get_id() {
    static uint16_t id = generate_template_data_flow_set_id();
    return id;
  }

  // Converts value to network byte order and appends it to the string
  constexpr static void append16(std::string &s, uint16_t value) {
    uint16_t nv = htons(value);
    s.append(std::string(reinterpret_cast<const char *>(&nv), sizeof(nv)));
  }

  constexpr static void append32(std::string &s, uint32_t value) {
    uint32_t nv = htonl(value);
    s.append(std::string(reinterpret_cast<const char *>(&nv), sizeof(nv)));
  }

  template <class T, class... ttypes>
  constexpr static void append_template_list(std::string &s) {
    if constexpr (std::is_base_of_v<IsStreamable, T>) {
      append16(s, T::field_type_in_h());
      append16(s, T::size_in_hbytes());
    }
    if constexpr (sizeof...(ttypes) != 0) {
      append_template_list<ttypes...>(s);
    }
  }

  template <class T, class... ttypes> constexpr static uint16_t value_length() {
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
  constexpr static void build_data(std::string &s, auto &itr) {
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
  constexpr static void clear_volatile_data(auto &itr) {
    if constexpr (std::is_base_of_v<IsStreamable, T>) {
      T::clear_if_volatile(itr);
    }
    if constexpr (sizeof...(ttypes) != 0) {
      clear_volatile_data<ttypes...>(itr);
    }
  }

  template <class T, class... ttypes>
  constexpr static uint16_t count_streamable() {
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
  constexpr static void ensure_no_mutex_object() {
    static_assert(!std::is_base_of_v<IsMutex, T>,
                  "You can only have one MUTEX entry in the definition");
    if constexpr (sizeof...(ttypes) != 0) {
      ensure_no_mutex_object<ttypes...>();
    }
  }

  template <class T, class... ttypes> constexpr static bool has_mutex_object() {
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
  constexpr static std::mutex &get_mutex_object(auto &itr) {
    static_assert(has_mutex_object<T, ttypes...>(), "Missing MUTEX entry");

    if constexpr (std::is_base_of_v<IsMutex, T>) {
      return T::get_mutex(itr);
    } else {
      return get_mutex_object<ttypes...>(itr);
    }
  }

  template <class T, class... ttypes>
  constexpr static void ensure_no_dirty_object() {
    static_assert(!std::is_base_of_v<IsDirty, T>,
                  "You can only have one DIRTY entry in the definition");
    if constexpr (sizeof...(ttypes) != 0) {
      ensure_no_dirty_object<ttypes...>();
    }
  }

  template <class T, class... ttypes> constexpr static bool has_dirty_object() {
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

  template <class T, class... ttypes>
  constexpr static bool &get_dirty_object(auto &itr) {
    static_assert(has_dirty_object<T, ttypes...>(), "Missing DIRTY entry");

    if constexpr (std::is_base_of_v<IsDirty, T>) {
      return T::get_dirty(itr);
    } else {
      return get_dirty_object<ttypes...>(itr);
    }
  }

public:
  constexpr static uint16_t count_elements() { return sizeof...(list); }

  constexpr static uint16_t sum_value_lengths() {
    return value_length<list...>();
  }

  constexpr static uint16_t get_packet_header_length() {
    return 40; // See RFC3954
  };

  constexpr static std::string generate_packet_header(uint32_t now_in_s,
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

  constexpr static std::string generate_template(uint32_t flow_set_id) {
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

  constexpr static void generate_flow_set_header(std::string &s,
                                                 uint16_t no_of_records) {
    append16(s, get_id());
    append16(s, get_flow_set_header_length() +
                    (no_of_records *
                     sum_value_lengths())); // Total length of package
  }

  constexpr static uint16_t get_flow_set_header_length() {
    return 4; // As per RFC3954
  };

  constexpr static std::string
  generate_flow_set_header(uint16_t no_of_records) {
    std::string s;
    s.reserve(get_flow_set_header_length());
    generate_flow_set_header(s, no_of_records);

    return s;
  }

  constexpr static void serialize(std::string &s, auto &itr) {
    build_data<list...>(s, itr);
  }

  constexpr static std::string serialize(auto &itr) {
    std::string s;
    s.reserve(sum_value_lengths()); // Reserve space for the entry
    serialize(s, itr);
    return s;
  }

  constexpr static void clear_volatile(auto &itr) {
    clear_volatile_data<list...>(itr);
  }

  template <class C>
  constexpr static uint32_t dump(LioLi::Tree &tree, C &container) {
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

// clang-format off
using ServiceMapOptionsFlowSet = NFSerializer<
  ServiceMapE<16 /* String size */, 26>
>;
// clang-format on

uint32_t Cache::ServiceMap::dump(LioLi::Tree &tree) {
  /* This code is WIP, and is currently crashing and rightfully leading to
  compiler warnings std::scoped_lock lock(mutex);
  */
  size_at_last_dump = service_map.size();

  return ServiceMapOptionsFlowSet::dump(tree, service_map);

  return 0;
}

void Cache::dump() {
  // clang-format off
  using DataFlowSet = NFSerializer<
  MUTEX<[](CacheMapType::iterator &itr) -> std::mutex & {return itr->second->mutex;}>,
  DIRTY<[](CacheMapType::iterator &itr) -> bool & {return itr->second->dirty;}>,
  E<&CacheElement2::ConstValues::ipv4_src_addr,   8 >,
  E<&CacheElement2::ConstValues::ipv4_dst_addr,   12>,
  E<&CacheElement2::ConstValues::l4_src_port,     7 >,
  E<&CacheElement2::ConstValues::l4_dst_port,     11>,
  E<&CacheElement2::ConstValues::src_mac,         56>,
  E<&CacheElement2::ConstValues::dst_mac,         57>,
  E<&CacheElement2::VolatileValues::in_bytes,     1 >,
  E<&CacheElement2::VolatileValues::in_pkts,      2 >,
  E<&CacheElement2::VolatileValues::out_bytes,    23>,
  E<&CacheElement2::VolatileValues::out_pkts,     24>,
  C<&CacheElement2::VolatileValues::service_key,  25>  // Treat the service key as if it is a constant
  >;
  // clang-format on

  LioLi::Tree buf;
  uint32_t sum_flow_sets;
  auto &logger = settings->get_logger();

  if (!logger.is_ready()) {
    return;
  }

  bool resend = logger.had_data_loss();

  // Generate data carrying flow sets
  {
    std::scoped_lock lock(mutex);

    sum_flow_sets = DataFlowSet::dump(buf, cache);

    auto curent_cache_size = cache.size();

    if (Pegs::s_peg_counts.max_cache_entries < curent_cache_size) {
      Pegs::s_peg_counts.max_cache_entries = curent_cache_size;
    }

    // Discard any entries that are no longer referenced
    for (auto itr = cache.begin(); itr != cache.end();) {
      auto old = itr++;

      // Delete entries that no-one knows about
      if (old->second.use_count() == 1) {
        cache.erase(old);
      }
    }
  }
  if (settings->get_generate_service_map() &&
      (!service_map.is_fully_flushed() || resend)) {
    uint32_t sm_flow_sets = service_map.dump(buf);

    sum_flow_sets += sm_flow_sets;

    assert(sum_flow_sets >=
           sm_flow_sets); // TODO: Handle overflow instead of crashing on it
  }

  auto now = Common::TestableTime::now<std::chrono::system_clock>(
      settings->get_testmode());
  uint32_t now_in_s =
      std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch())
          .count();

  // Transmit templates if anything happened to the connection
  if (resend) {
    LioLi::Tree out_tree;
    if (settings->get_generate_service_map()) {
      out_tree << (LioLi::Tree("PacketHeader")
                   << DataFlowSet::generate_packet_header(
                          now_in_s, sequence_number++,
                          settings->get_source_id(), 2))
               << (LioLi::Tree("TemplateFlowSet_DataFlowSet")
                   << DataFlowSet::generate_template(0))
               << (LioLi::Tree("TemplateFlowSet_ServiceMap")
                   << ServiceMapOptionsFlowSet::generate_template(0));
    } else {
      out_tree << (LioLi::Tree("PacketHeader")
                   << DataFlowSet::generate_packet_header(
                          now_in_s, sequence_number++,
                          settings->get_source_id(), 1))
               << (LioLi::Tree("TemplateFlowSet_DataFlowSet")
                   << DataFlowSet::generate_template(0));
    }
    logger << std::move(out_tree);
    Pegs::s_peg_counts.logs_written++;
  }

  if (settings->get_do_ping()) {
    LioLi::Tree out_tree;
    out_tree << (LioLi::Tree("PacketHeader_ping")
                 << DataFlowSet::generate_packet_header(
                        now_in_s, sequence_number++, settings->get_source_id(),
                        0));
    logger << std::move(out_tree);

    ping_count++;

    if (next_screen_ping_at_s <= now_in_s) {
      snort::LogMessage("Netflow2 ping %u at %u\n", ping_count, now_in_s);

      next_screen_ping_at_s = now_in_s + 10;
    }
  }

  if (buf.has_data()) {
    LioLi::Tree out_tree;
    out_tree << (LioLi::Tree("PacketHeader")
                 << DataFlowSet::generate_packet_header(
                        now_in_s, sequence_number++, settings->get_source_id(),
                        sum_flow_sets));
    // The buf tree is root based, using "<<" would give the data path
    // root-root-data
    out_tree.merge(std::move(buf));
    logger << std::move(out_tree);
    Pegs::s_peg_counts.logs_written++;
  }
}

void Cache::test_loop() {
  std::unique_lock lock(worker_mutex);

  // In testmode we don't do anything until terminating
  while (!terminate) {
    cv.wait_for(lock,
                std::chrono::milliseconds(settings->get_flush_interval_ms()),
                [this] { return terminate; });
  }

  lock.unlock();
  dump(); // This might take some time, don't keep the worker mutex
  lock.lock();

  worker_done = true;

  cv.notify_all();
}

void Cache::worker_loop() {
  std::unique_lock lock(worker_mutex);

  // Main loop
  while (!terminate) {
    worker_kicked = false;

    lock.unlock();
    dump(); // This might take some time, don't keep the worker mutex
    lock.lock();

    cv.wait_for(lock,
                std::chrono::milliseconds(settings->get_flush_interval_ms()),
                [this] { return terminate || worker_kicked; });

    if (worker_kicked) {
      snort::LogMessage("Netflow2 worker kicked\n");
    } else {
      snort::LogMessage("Netflow2 worker not kicked\n");
    }
  }

  // We are done
  worker_done = true;

  cv.notify_all();
}

void Cache::kick_worker() {
  std::unique_lock lock(worker_mutex);
  worker_kicked = true;
  cv.notify_all();
}

void Cache::start_worker() {
  terminate = false;
  worker_done = false;
  if (settings->get_testmode()) {
    worker_thread = std::thread{&Cache::test_loop, this};
  } else {
    worker_thread = std::thread{&Cache::worker_loop, this};
  }
}

void Cache::stop_worker() {
  // Check worker is running
  if (worker_thread.joinable()) {
    std::unique_lock lock(worker_mutex);

    // If thread hasn't killed it self
    if (!worker_done) {
      terminate = true;

      // Kick worker, we do not release the lock, as we need to reach
      // wait_for(..) before the worker is allowed to continue
      cv.notify_all();

      // Give worker a chance to go down gracefully
      cv.wait_for(lock, std::chrono::seconds(2),
                  [this] { return worker_done; });

      if (!worker_done) {
        // Still not done, set it free
        worker_thread.detach();
        return;
      }
    }
    worker_thread.join();
  }
}

} // namespace trout_netflow2
