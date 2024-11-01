
// Snort includes

// System includes
#include <regex>

// Local includes
#include "lioli_path.h"

// Global includes

// Debug includes

namespace LioLi {

Path::Path(std::string path) : path(path) {}

const static std::regex valid_node_name("\\$|#?[a-z_][a-z_\\d]*",
                                        std::regex::optimize);

bool Path::is_valid_node_name(const std::string &name) {
  return std::regex_match(name, valid_node_name);
}

const static std::regex valid_path_name("\\$(\\.#?[a-z_][a-z_\\d]*)",
                                        std::regex::optimize);

bool Path::is_valid_path_name(const std::string &name) {
  return std::regex_match(name, valid_path_name);
}

} // namespace LioLi
