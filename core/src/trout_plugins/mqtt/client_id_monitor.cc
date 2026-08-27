
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes

// System includes

// Global includes

// Local includes
#include "client_id_monitor.h"
#include "mqtt_protocol_defs.h"

// Debug includes

namespace mqtt_plugin {

ClientIDMonitor::ClientIDMonitor(uint32_t min_size) :
  min_size(min_size) {}

bool ClientIDMonitor::check(const std::span<const uint8_t> &client_id, snort::SfIp &sf_ip) {
  // First part is happy path, we don't modify anything and just need
  // a shared lock
  {
    std::shared_lock shared_lock(mutex);

    auto in_current = map_current.find(client_id);

    if (in_current != map_current.end() && in_current->second == sf_ip) {
      return true;
    }
  }

  // If we come here we know we need to modify something, and hence
  // need a unique lock, releasing the shared lock means we don't
  // know anything about the state of map_current at this point
  {
    std::unique_lock unique_lock(mutex);

    auto in_current = map_current.find(client_id);

    if (in_current != map_current.end()) {
      if (in_current->second == sf_ip) {
        return true;
      }

      in_current->second = sf_ip;
      return false;
    }

    if (map_current.size() <= min_size) {
      auto in_previous = map_previous.find(client_id);

      if (in_previous != map_previous.end()) {
        auto extracted = map_previous.extract(in_previous);

        auto result = map_current.insert(std::move(extracted));

        if (result.position->second == sf_ip) {
          return true;
        }

        result.position->second = sf_ip;
        return false;
      }
    } else {
      map_previous.clear();
      map_previous.swap(map_current);

      // TODO: Add peg for how much map_previous contained before being cleared
    }

    std::vector<uint8_t> vector_client_id = to_vector(client_id);
    map_current.emplace(std::move(vector_client_id), sf_ip);

    return false;
  }
}


} // namespace mqtt_plugin
