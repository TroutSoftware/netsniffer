// Snort includes

// System includes

// Global includes

// Local includes
#include "settings.h"

// Debug includes
#include <iostream>

namespace capture_pcap {

Settings::Settings(const char* module_name) : module_name(module_name) {

}

bool Settings::begin(const char* s, int i) {
  std::cout << "MKRTEST: begin called on \"" << s << "\" index:" << i << std::endl;
  
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
  std::cout << "MKRTEST: end called on \"" << s << "\" index:" << i << std::endl;

  if (module_name == s) {
    // TODO: Validate settings
    return true;
  }

  if (module_name + ".map" == s) {
    if (!current_item) {
      snort::ErrorMessage("ERROR: Internal parsing error on %s, end with no beginning", s);
      return false;
    }
    if (0 == i && !current_item->filter && !current_item->dumper) {
      // Default item didn't have a configuration, ignoring it
      current_item.reset();
      return true;
    }
    if (!current_item->filter || !current_item->filter->is_valid()) {
      snort::ErrorMessage("ERROR: filter missing or not valid");
      return false;
    }
    if (!current_item->dumper) {
      snort::ErrorMessage("ERROR: dumper missing or not valid");
      return false;    
    }

    map.emplace(current_item);
    current_item.swap(zero_item);
    return true;
  }
  
  return false;
}

bool Settings::set(const char *s, snort::Value &val) {
  std::cout << "MKRTEST: set(\"" << s << "\", \"" << val.get_name() << "\", ...)" << std::endl;
  if (val.is("snap_length")) {
    snaplen = val.get_int32();
  } else if (val.is("optimize_filter")) {
    optimize_filter = val.get_bool();
  } else if (val.is("rotate_limit")) {
    rotate_limit = val.get_int32();
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
}

} // namespace capture_pcap {
