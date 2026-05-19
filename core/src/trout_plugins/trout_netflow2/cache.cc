
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes
#include <flow/flow_key.h>
#include <protocols/eth.h>

// System includes
#include <chrono>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string>
#include <type_traits>

// Global includes
#include "../includes/testable_time.h"

// Local includes
#include "cache.h"
#include "cache_template_serializer.h"
#include "pegs.h"
#include "settings.h"

// Debug includes

namespace trout_netflow2 {

Cache::Cache(const char *name, std::shared_ptr<Settings> settings)
    : LioLi::ModuleWorker(name), settings(settings) {
  assert(settings);

  start_worker();
}

Cache::~Cache() {}

void Cache::shutdown() { stop_worker(); }

std::shared_ptr<Cache> Cache::create_cache(std::shared_ptr<Settings> settings,
                                           const char *my_name) {
  std::shared_ptr<Cache> cache(new Cache(my_name, settings));

  // Register in logframework for controlled shutdown
  LioLi::LogDB::register_instance(cache);

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
  // TODO: Rethink how this is written, could probably be done more
  //       readable with a template or something...
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
                  ((lhs.dst_mac <=> rhs.dst_mac) < 0 ||
                   ((lhs.dst_mac <=> rhs.dst_mac) == 0 &&
                    (lhs.protocolIdentifier <
                     rhs.protocolIdentifier))))))))))));
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
  data->service_name = s;
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
      Pegs::s_peg_counts.ipv6_flows_ignored++;
      return std::make_shared<CacheElement2::VolatileValues>();
    }
    if (p->ptrs.ip_api.get_dst()->is_ip4()) {
      *reinterpret_cast<uint32_t *>(key.ipv4_dst_addr.data()) =
          p->ptrs.ip_api.get_dst()->get_ip4_value();
    } else {
      // TODO: Handle IPv6 for dst, for now just return dummy element
      Pegs::s_peg_counts.ipv6_flows_ignored++;
      return std::make_shared<CacheElement2::VolatileValues>();
    }

    if (p->is_tcp() || p->is_udp()) {
      key.l4_src_port = p->ptrs.sp;
      key.l4_dst_port = p->ptrs.dp;
    }
  }

  key.protocolIdentifier = protocol_from_package(p);

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
    data->service_name = p->flow->service;
  }

  data->dirty = true;

  return data;
}

// clang-format off
using ServiceMapOptionsFlowSet = NFSerializer<
  ServiceMapE<16 /* String size */, 26>
>;
// clang-format on

uint32_t Cache::ServiceMap::dump(LioLi::Tree &tree) {

  size_at_last_dump = service_map.size();

  return ServiceMapOptionsFlowSet::dump(tree, service_map);

  return 0;
}

void Cache::dump() {
  // clang-format off
  using DataFlowSet = NFSerializer<
  MUTEX<[](CacheMapType::iterator &itr) -> std::mutex & {return itr->second->mutex;}>,
  DIRTY<[](CacheMapType::iterator &itr) -> bool & {return itr->second->dirty;}>,
  E<&CacheElement2::ConstValues::ipv4_src_addr,       8>,
  E<&CacheElement2::ConstValues::ipv4_dst_addr,       12>,
  E<&CacheElement2::ConstValues::l4_src_port,         7 >,
  E<&CacheElement2::ConstValues::l4_dst_port,         11>,
  E<&CacheElement2::ConstValues::src_mac,             56>,
  E<&CacheElement2::ConstValues::dst_mac,             57>,
  E<&CacheElement2::ConstValues::protocolIdentifier,  4 >,
  E<&CacheElement2::VolatileValues::in_bytes,         1 >,
  E<&CacheElement2::VolatileValues::in_pkts,          2 >,
  E<&CacheElement2::VolatileValues::out_bytes,        23>,
  E<&CacheElement2::VolatileValues::out_pkts,         24>,
  C<&CacheElement2::VolatileValues::service_key,      25>  // Treat the service key as if it is a constant (i.e. it won't be cleared when sending)
  //CVS<&CacheElement2::VolatileValues::service_name,   96, 30 /* Max number of chars to transmit */>   // Treat the service name as a constant, so it isn't cleared
  >;
  // clang-format on

  if (settings->get_extended_console_logging()) {
    snort::LogMessage("Netflow2 dump entered\n");
  }

  LioLi::Tree buf;
  uint32_t sum_flow_sets = 0;
  auto &logger = settings->get_logger();

  if (!logger.is_ready()) {
    if (settings->get_extended_console_logging()) {
      snort::LogMessage("Netflow2 aborting dump, logger not ready\n");
    }
    return;
  }

  // Get the current time
  auto now = Common::TestableTime::now<std::chrono::system_clock>(
      settings->get_testmode());
  uint32_t now_in_s =
      std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch())
          .count();

  auto now_steady = Common::TestableTime::now<std::chrono::steady_clock>(
      settings->get_testmode());
  uint32_t now_in_s_steady = std::chrono::duration_cast<std::chrono::seconds>(
                                 now_steady.time_since_epoch())
                                 .count();

  bool resend =
      logger_loss_tracker || logger.has_lost_data(logger_loss_tracker);
  logger_loss_tracker.clear_dirty();

  if (settings->get_template_resend_interval_s() != 0) {
    resend |= next_template_at_s < now_in_s_steady;

    if (resend) {
      next_template_at_s =
          now_in_s_steady + settings->get_template_resend_interval_s();
    }
  }

  // Potentially send service map
  if (settings->get_generate_service_map() &&
      (!service_map.is_fully_flushed() || resend)) {

    if (settings->get_extended_console_logging()) {
      snort::LogMessage("Netflow2 dumping service maps\n");
    }

    uint32_t sm_flow_sets = service_map.dump(buf);

    sum_flow_sets += sm_flow_sets;

    assert(sum_flow_sets >=
           sm_flow_sets); // TODO: Handle overflow instead of crashing on it
  }

  // Generate data carrying flow sets
  {
    std::scoped_lock lock(mutex);

    uint32_t data_flow_sets = DataFlowSet::dump(buf, cache);

    sum_flow_sets += data_flow_sets;

    assert(sum_flow_sets >=
           data_flow_sets); // TODO: Handle overflow instead of crashing on it

    auto curent_cache_size = cache.size();

    if (Pegs::s_peg_counts.max_cache_entries < curent_cache_size) {
      Pegs::s_peg_counts.max_cache_entries = curent_cache_size;
    }

    if (settings->get_extended_console_logging()) {
      snort::LogMessage("Netflow2 cleanup of abandoned cache entries\n");
    }

    // Discard any entries that are no longer referenced
    for (auto itr = cache.begin(); itr != cache.end();) {
      auto old = itr++;

      // Delete entries that no-one knows about
      if (old->second.use_count() == 1) {
        cache.erase(old);
      }
    }

    if (settings->get_extended_console_logging()) {
      snort::LogMessage("Netflow2 done cleanup of abandoned cache entries\n");
    }
  }

  // Transmit templates if anything happened to the connection
  if (resend) {
    if (settings->get_extended_console_logging()) {
      snort::LogMessage("Netflow2 generating packet headers\n");
    }

    // Generate the templates once, and reuse...
    static const std::string data_flow_set_template =
        DataFlowSet::generate_template(0);
    static const std::string service_map_template =
        ServiceMapOptionsFlowSet::generate_template(0);

    LioLi::Tree out_tree;
    if (settings->get_generate_service_map()) {
      out_tree << (LioLi::Tree("PacketHeader")
                   << DataFlowSet::generate_packet_header(
                          now_in_s, sequence_number++,
                          settings->get_source_id(), 2))
               << (LioLi::Tree("TemplateFlowSet_DataFlowSet")
                   << data_flow_set_template)
               << (LioLi::Tree("TemplateFlowSet_ServiceMap")
                   << service_map_template);
    } else {
      out_tree << (LioLi::Tree("PacketHeader")
                   << DataFlowSet::generate_packet_header(
                          now_in_s, sequence_number++,
                          settings->get_source_id(), 1))
               << (LioLi::Tree("TemplateFlowSet_DataFlowSet")
                   << data_flow_set_template);
    }
    logger << std::move(out_tree);
    Pegs::s_peg_counts.logs_written++;

    if (settings->get_extended_console_logging()) {
      snort::LogMessage("Netflow2 done generating packet headers\n");
    }
  }

  if (settings->get_do_ping()) {
    LioLi::Tree out_tree;
    out_tree << (LioLi::Tree("PacketHeader_ping")
                 << DataFlowSet::generate_packet_header(
                        now_in_s, sequence_number++, settings->get_source_id(),
                        0));
    logger << std::move(out_tree);

    ping_count++;

    if (settings->get_extended_console_logging() &&
        next_screen_ping_at_s <= now_in_s_steady) {
      // Note, we use system_clock for the timestamp
      snort::LogMessage("Netflow2 ping %u at %u\n", ping_count, now_in_s);

      next_screen_ping_at_s = now_in_s_steady + 10;
    }
  }

  if (buf.has_data()) {
    if (settings->get_extended_console_logging()) {
      snort::LogMessage("Netflow2 moving dump data to logger\n");
    }

    LioLi::Tree out_tree;
    out_tree << (LioLi::Tree("PacketHeader_data")
                 << DataFlowSet::generate_packet_header(
                        now_in_s, sequence_number++, settings->get_source_id(),
                        sum_flow_sets));
    // The buf tree is root based, using "<<" would give the data path
    // root-root-data
    out_tree.merge(std::move(buf));
    logger << std::move(out_tree);
    Pegs::s_peg_counts.logs_written++;

    if (settings->get_extended_console_logging()) {
      snort::LogMessage("Netflow2 done moving dump data to logger\n");
    }
  }

  if (settings->get_extended_console_logging()) {
    snort::LogMessage("Netflow2 leaving dump with normal exit\n");
  }
}

void Cache::test_loop() {
  snort::LogMessage("Netflow2 using test loop\n");
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
  if (settings->get_extended_console_logging()) {
    snort::LogMessage("Netflow2 using normal worker_loop loop\n");
  }
  std::unique_lock lock(worker_mutex);

  // Main loop
  while (true) {
    worker_kicked = false;

    // Remember the state of pre-dump to avoid races
    bool terminate_pre_dump = terminate;

    lock.unlock(); // The dump can take time, don't block others
    dump();
    lock.lock();

    if (terminate_pre_dump)
      break;

    cv.wait_for(lock,
                std::chrono::milliseconds(settings->get_flush_interval_ms()),
                [this] { return terminate || worker_kicked; });

    if (settings->get_extended_console_logging()) {
      if (worker_kicked) {
        snort::LogMessage("Netflow2 worker kicked (%i)\n",
                          settings->get_flush_interval_ms());
      } else {
        snort::LogMessage("Netflow2 worker not kicked (%i)\n",
                          settings->get_flush_interval_ms());
      }
    }
  }

  if (settings->get_extended_console_logging()) {
    snort::LogMessage("Netflow2 worker terminating\n");
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

uint8_t Cache::protocol_from_package(snort::Packet *p) {
  assert(p);

  if (!p->has_ip()) {
    return settings->get_undefined_ip_protocol_number();
  }

  if (p->flow && p->flow->key) {
    return p->flow->key->ip_protocol;
  }

  if (!p->layers || p->num_layers == 0) {
    return settings->get_undefined_ip_protocol_number();
  }

  if (p->is_ip4()) {
    for (uint8_t i = 0; i < p->num_layers; i++) {

      const auto &layer = p->layers[i];

      if (layer.length >= sizeof(struct iphdr)) {
        const auto *h = reinterpret_cast<const struct iphdr *>(layer.start);

        if (h && h->version == 4) {
          return h->protocol;
        }
      }
    }
  } else if (p->is_ip6()) {
    static_assert(sizeof(uint8_t) == sizeof(p->num_layers));
    for (uint8_t i = 0; i < p->num_layers; i++) {
      const auto &layer = p->layers[i];

      if (layer.length >= sizeof(struct ip6_hdr)) {
        const auto *h = reinterpret_cast<const struct ip6_hdr *>(layer.start);

        if (h && (h->ip6_vfc & 0xF0) == 0x60) {
          return h->ip6_nxt;
        }
      }
    }
  }

  return settings->get_undefined_ip_protocol_number();
}

} // namespace trout_netflow2
