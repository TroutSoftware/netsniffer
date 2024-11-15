
#ifndef lioli_path_3f818a1f
#define lioli_path_3f818a1f

// Snort includes

// System includes
#include <map>
#include <string>

// Local includes
#include "lioli.h"

// Global includes

// Debug includes

namespace LioLi {

class Path {
  using Map = std::map<std::string, Tree>;
  Map relative;
  Map absolute;
  Map::iterator me;

public:
  Path(const Path &);
  Path(Path &&);
  Path(std::string path = "$");

  Path &operator=(const Path &);
  Path &operator=(Path &&);

  bool operator==(const Path &path) const;

  constexpr static std::string regex_node_name() {
    return "\\$|#?\\w[\\w\\d]*";
  }
  static bool is_valid_node_name(const std::string &name);

  constexpr static std::string regex_path_name() {
    return "\\$(\\.#?\\w[\\w\\d]*)*";
  }
  bool is_valid_path_name() const { return is_valid_path_name(me->first); }
  static bool is_valid_path_name(const std::string &name);

  bool is_absolute() const;
  bool is_relative() const;

  static bool is_absolute(const std::string &path) {
    return path.starts_with("$");
  }
  static bool is_relative(const std::string &path) {
    return !is_absolute(path);
  }

  Path &operator<<(const std::string &text);
  Path &operator<<(const int number);
  Path &operator<<(const Tree &tree);
  Path &operator<<(Tree &&tree);
  Path &operator<<(const Path &path);
  Path &operator<<(Path &&path);

  uint32_t hash() const {
    return (me->first.length() + me->second.hash()) ^
           (relative.size() + (absolute.size() << 8));
  } // Very fast and simple hash function

  Tree to_tree() const;
};

} // namespace LioLi

#endif // #ifndef lioli_path_validator_3f818a1f
