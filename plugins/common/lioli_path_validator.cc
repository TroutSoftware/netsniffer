
// Snort includes

// System includes
#include <regex>

// Local includes
#include "lioli_path_validator.h"

// Global includes

// Debug includes

namespace LioLi {

const static std::regex valid_node_name("[a-z_][a-z_\\d]*|\\$",
                                        std::regex::optimize);

bool PathValidator::is_valid_node_name(const std::string &name) {
  return std::regex_match(name, valid_node_name);
}

} // namespace LioLi
