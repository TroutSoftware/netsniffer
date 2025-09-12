
// Snort includes
#include <protocols/eth.h>

// System includes
#include <arpa/inet.h>
#include <endian.h>
#include <string>
#include <type_traits>

// Global includes

// Local includes
#include "cache.h"
#include "pegs.h"
#include "settings.h"

// Debug includes
#include <iostream>

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

Cache::ServiceMap::ServiceKey
Cache::ServiceMap::get_add(const char *service_name) {
  std::scoped_lock lock(mutex);
  return (service_map.emplace(service_name, service_map.size()).first)->second;
}

Cache::ServiceMap::ServiceKey
Cache::ServiceMap::get_add(const std::string &service_name) {
  return get_add(service_name.c_str());
}

std::size_t Cache::ServiceMap::size() { return service_map.size() - 1; }

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
  ServiceMap::ServiceKey key = cache->service_map.get_add(s);

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

  // TODO: Remove after test
  // dump();

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

// Template used to declare data entries for the binary netflow format
// fixed_size denotes the size for the field in the binary data, even
// the member (v) has a different size (Must be 0, 1, 2, 4 or 8, where 0
// means use the real size of v)
template <auto v, int key, uint16_t fixed_size = 0> class E {
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
    append16(s, T::field_type_in_h());
    append16(s, T::size_in_hbytes());
    if constexpr (sizeof...(ttypes) != 0) {
      append_template_list<ttypes...>(s);
    }
  }

  template <class T, class... ttypes> constexpr static uint16_t value_length() {
    if constexpr (sizeof...(ttypes) != 0) {
      return value_length<ttypes...>() + T::size_in_hbytes();
    }
    return T::size_in_hbytes();
  }

  template <class T, class... ttypes>
  constexpr static void build_data(std::string &s,
                                   Cache::CacheMapType::iterator &itr) {
    T::append_value(s, itr);
    if constexpr (sizeof...(ttypes) != 0) {
      build_data<ttypes...>(s, itr);
    }
  }

  template <class T, class... ttypes>
  constexpr static void
  clear_volatile_data(Cache::CacheMapType::iterator &itr) {
    T::clear_if_volatile(itr);
    if constexpr (sizeof...(ttypes) != 0) {
      clear_volatile_data<ttypes...>(itr);
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

  constexpr static std::string generate_packet_header(uint32_t sequence_number,
                                                      uint16_t flow_set_count) {
    std::string s;
    s.reserve(get_packet_header_length());
    append16(s, 9);              // The version of binary netflow we adhere to
    append16(s, flow_set_count); // Number of flow sets in the packet
    append32(s, 0);              // TODO: add up time (seconds since boot)
    append32(s, 0);              // TODO: add unix time in seconds
    append32(s, sequence_number);
    append32(s, 0); // TODO: add unique number identifying me

    assert(s.length() != get_packet_header_length());

    return s;
  }

  constexpr static std::string generate_template() {
    std::string s;
    const uint16_t length = 4 * count_elements() + 8 /* Header size */;
    s.reserve(length);

    // See RFC3954 for format
    append16(s, 0);      // FlowSet ID 0 = Template format
    append16(s, length); // Total length of package
    append16(s, get_id());
    append16(s, count_elements());

    append_template_list<list...>(s); // Add the template data from each element

    return s;
  }

  constexpr static void generate_data_flow_set_header(std::string &s,
                                                      uint16_t no_of_records) {
    append16(s, get_id());
    append16(
        s, 4 + (no_of_records *
                sum_value_lengths())); // the +4 is for the ID and length fields
  }

  constexpr static uint16_t get_data_flow_set_header_length() {
    return 4; // As per RFC3954
  };

  constexpr static std::string
  generate_data_flow_set_header(uint16_t no_of_records) {
    std::string s;
    s.reserve(get_data_flow_set_header_length());
    generate_data_flow_set_header(s, no_of_records);

    return s;
  }

  constexpr static void serialize(std::string &s,
                                  Cache::CacheMapType::iterator &itr) {
    build_data<list...>(s, itr);
  }

  constexpr static std::string serialize(Cache::CacheMapType::iterator &itr) {
    std::string s;
    s.reserve(sum_value_lengths()); // Reserve space for the entry
    serialize(s, itr);
    return s;
  }

  constexpr static void clear_volatile(Cache::CacheMapType::iterator &itr) {
    clear_volatile_data<list...>(itr);
  }
};

void Cache::dump() {
  // clang-format off
    using Serializer = NFSerializer<
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
      E<&CacheElement2::VolatileValues::service_key,  25>
    >;
  // clang-format on

  std::scoped_lock cache_lock(mutex);

  constexpr const static uint16_t max_to_send =
      (UINT16_MAX - Serializer::get_data_flow_set_header_length()) /
      Serializer::sum_value_lengths();

  Cache::CacheMapType::iterator itr = cache.begin();

  while (itr != cache.end()) {

    uint16_t entries_prepared = 0;
    std::string out_buffer;
    out_buffer.reserve(
        UINT16_MAX); // Note, a netflow FlowSet is limited to 64Kb

    while (entries_prepared < max_to_send && itr != cache.end()) {
      assert(itr->second);
      std::scoped_lock lock(itr->second->mutex);
      if (itr->second->dirty) {
        Serializer::serialize(out_buffer, itr);
        Serializer::clear_volatile(itr);
        itr->second->dirty = false;
        entries_prepared++;
      }

      auto old = itr++;

      // Delete entries that no-one knows about
      if (old->second.use_count() == 1) {
        cache.erase(old);
      }
    }

    // Bail, if nothing to do
    if (entries_prepared == 0)
      break;

    LioLi::Tree buf;

    if (settings->get_logger().had_data_loss()) {
      buf << std::move(LioLi::Tree("PacketHeader")
                       << Serializer::generate_packet_header(
                              sequence_number++, 2 /* packet count */));
      buf << std::move(LioLi::Tree("TemplateFlowSet")
                       << Serializer::generate_template());
    } else {
      buf << std::move(LioLi::Tree("PacketHeader")
                       << Serializer::generate_packet_header(
                              sequence_number++, 1 /* packet count */));
    }

    buf << std::move(
        LioLi::Tree("DataFlowSet")
        << Serializer::generate_data_flow_set_header(
               entries_prepared) // TODO: Check if std::move is needed
        << out_buffer);

    settings->get_logger() << std::move(buf);
  }
}

void Cache::worker_loop() {
  std::unique_lock lock(worker_mutex);
  // Main loop
  while (!terminate) {
    worker_kicked = false;

    lock.unlock();
    dump(); // This might take some time, don't keep the worker mutex
    lock.lock();

    cv.wait_for(lock, std::chrono::milliseconds(settings->get_flush_interval_ms()),
                [this] { return terminate || worker_kicked; });
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
  worker_thread = std::thread{&Cache::worker_loop, this};
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
