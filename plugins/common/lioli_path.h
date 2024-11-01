
#ifndef lioli_path_3f818a1f
#define lioli_path_3f818a1f

// Snort includes

// System includes
#include <string>

// Local includes
#include "lioli.h"

// Global includes

// Debug includes

namespace LioLi {

class Path {
  std::string path;

public:
  Path(std::string path);

  static bool is_valid_node_name(const std::string &name);

  bool is_valid_path_name() { return is_valid_path_name(path); }
  static bool is_valid_path_name(const std::string &name);
};

} // namespace LioLi

#endif // #ifndef lioli_path_validator_3f818a1f
