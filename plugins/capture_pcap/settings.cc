// Snort includes

// System includes

// Global includes

// Local includes
#include "settings.h"

// Debug includes

namespace capture_pcap {

Settings::Settings(const char* module_name, PegCounts &pegs) : pegs(pegs), module_name(module_name) {

}

bool Settings::begin(const char* s, int) {
  // Check if this is a fresh load of settings
  if (module_name == s) {
    reset();
    return true;
  }

  // Processing the map
  if (module_name + ".map" == s) {
    if (current_item) {
      if (zero_item) {
        snort::ErrorMessage("ERROR: Internal parsing error on %s", s);
        return false;
      }
      current_item.swap(zero_item);
    }
    current_item.reset(new MapItem);
    return true;
  }

  // We got something in that we don't know how to handle
  return false;
}

bool Settings::end(const char* s, int i) {
  if (module_name == s) {
    // TODO: Validate settings
    return true;
  }

  if (module_name + ".map" == s) {
    if (!current_item) {
      snort::ErrorMessage("ERROR: Internal parsing error on %s, end with no beginning\n", s);
      return false;
    }
    if (0 == i && !current_item->filter && !current_item->dumper) {
      // Default item didn't have a configuration, ignoring it
      current_item.reset();
      return true;
    }
    if (!current_item->filter || !current_item->filter->is_valid()) {
      snort::ErrorMessage("ERROR: filter missing or not valid\n");
      return false;
    }
    if (!current_item->dumper) {
      snort::ErrorMessage("ERROR: pcap_prefix missing or not valid\n");
      return false;
    }

    map.emplace_back(current_item.release());
    current_item.swap(zero_item);
    return true;
  }

  return false;
}

bool Settings::set(const char *, snort::Value &val) {
  if (val.is("snap_length")) {
    snaplen = val.get_int32();
  } else if (val.is("testmode")) {
    testmode = val.get_bool();
  } else if (val.is("optimize_filter")) {
    optimize_filter = val.get_bool();
  } else if (val.is("rotate_limit")) {
    rotate_limit = val.get_int32();
  } else if (val.is("filter")) {
    assert(current_item);
    current_item->filter = std::make_unique<Filter>(val.get_as_string(), shared_from_this(), pegs);
    return current_item->filter->is_valid();
  } else if (val.is("pcap_prefix")) {
    assert(current_item);
    std::string key = val.get_as_string();
    std::shared_ptr<PcapDumper> dumper;
    auto itr = dumper_map.find(key);

    if (itr != dumper_map.end()) {
      dumper = itr->second.lock();
    }

    if (!dumper) {
      dumper.reset(new PcapDumper(key, shared_from_this(), pegs));
      dumper_map[key] = std::move(dumper);
    }

    current_item->dumper = dumper;
  } else if (val.is("hint_ip")) {
    assert(current_item);
    uint8_t addr[4];
    val.get_addr_ip4(addr);
    current_item->ip = *reinterpret_cast<uint32_t*>(addr);
  } else if (val.is("hint_port")) {
    assert(current_item);
    current_item->port = val.get_uint16();
  } else {
    // fail if we didn't get something valid
    return false;
  }

  return true;
}

void Settings::reset() {
  // NOTE: Some values have their defaults from the module_params in module.cc
  map.clear();
  zero_item.reset();
  current_item.reset();

  // The dumper map will not be cleared, as existing flows will continue to write to a given dumper,
  // but we will do a cleanup of unused entries
  for (auto itr = dumper_map.begin(); itr != dumper_map.end();) {
    if (itr->second.lock()) {
      itr++;
    } else {
      itr = dumper_map.erase(itr);
    }
  }
}

} // namespace capture_pcap {
