
// Snort includes

// System includes
#include <cassert>
#include <regex>

// Local includes
#include "lioli_path.h"

// Global includes

// Debug includes

namespace LioLi {

Path::Path(const Path &src) : relative(src.relative), absolute(src.absolute) {
  me = (src.is_absolute() ? absolute : relative).find(src.me->first);

  assert(me != absolute.end() && me != relative.end());
}

Path::Path(Path &&src) { *this = std::move(src); }

Path &Path::operator=(const Path &src) {
  relative = src.relative;
  absolute = src.absolute;

  me = (src.is_absolute() ? absolute : relative).find(src.me->first);

  return *this;
}

Path &Path::operator=(Path &&src) {
  std::string my_name = src.me->first;

  relative = std::move(src.relative);
  absolute = std::move(src.absolute);

  me = (src.is_absolute() ? absolute : relative).find(src.me->first);

  assert(me != absolute.end() && me != relative.end());

  return *this;
}

Path::Path(std::string path_name) {
  auto &map = (is_absolute(path_name) ? absolute : relative);

  auto r = map.emplace(std::move(path_name), std::move(Tree()));

  assert(r.second);

  me = r.first;
}

bool Path::operator==(const Path &path) const {
  if (me->first == path.me->first && relative.size() == path.relative.size() &&
      absolute.size() == path.absolute.size()) {
    // If all the easy checks are ok, we need to check
    // each element
    for (auto &itr : relative) {
      auto pitr = path.relative.find(itr.first);
      if (pitr == path.relative.end() || itr.first != pitr->first ||
          itr.second != pitr->second) {
        return false;
      }
    }
    for (auto &itr : absolute) {
      auto pitr = path.absolute.find(itr.first);
      if (pitr == path.absolute.end() || itr.first != pitr->first ||
          itr.second != pitr->second) {
        return false;
      }
    }
  }
  return false;
}

const static std::regex valid_node_name("\\$|#?[a-z_][a-z_\\d]*",
                                        std::regex::optimize);

bool Path::is_valid_node_name(const std::string &node_name) {
  return std::regex_match(node_name, valid_node_name);
}

// TODO: When we enable relative paths, the initial "$." should be optional
const static std::regex valid_path_name("\\$(\\.#?[a-z_][a-z_\\d]*)*",
                                        std::regex::optimize);

bool Path::is_valid_path_name(const std::string &path_name) {
  return std::regex_match(path_name, valid_path_name);
}

bool Path::is_absolute() const { return is_absolute(me->first); }

bool Path::is_relative() const { return is_relative(me->first); }

Path &Path::operator<<(const std::string &text) {
  me->second << text;
  return *this;
}

Path &Path::operator<<(const int number) {
  me->second << number;
  return *this;
}

Path &Path::operator<<(const Tree &tree) {
  me->second << tree;
  return *this;
}

Path &Path::operator<<(Tree &&tree) {
  me->second << std::move(tree);
  return *this;
}

Path &Path::operator<<(const Path &path) {

  Path tmp = path;
  return *this << std::move(tmp);
}

Path &Path::operator<<(Path &&path) {
  // Relative path should be prefixed with our name, if we are absolute,
  // relative paths also becomes absolute
  Map &target = (is_absolute() ? absolute : relative);

  for (auto &iter : path.relative) {
    auto r = target.emplace(me->first + '.' + iter.first, iter.second);

    // If we couldn't add, then we need to merge
    if (!r.second) {
      r.first->second.merge(iter.second);
    }
  }

  path.relative.clear();

  // Absolute paths are added to our absolute list, if there are conflicts, the
  // result trees should be merged
  absolute.merge(path.absolute);

  if (!path.absolute.empty()) {
    for (auto &iter : path.absolute) {
      auto ele = absolute.find(iter.first);
      assert(ele != absolute.end()); // Coding error if this fires, absolute
                                     // should only contain duplicates

      ele->second.merge(iter.second);
    }
  }

  path.absolute.clear();

  return *this;
}

Tree Path::to_tree() const {
  assert(relative.size() == 0); // We can't generate a relative tree

  class Node {
    Tree me = {"$"};
    std::map<std::string, Node> map;

  public:
    void add(std::string key, Tree &value) {
      size_t pos = std::string("$.").size(); // We skip the initial "$.", string
                                             // funcs are constexpr (C++20)
      Node *node = this;
      while (pos < key.size()) {
        auto new_pos = key.find('.', pos);
        std::string sub_key;

        if (new_pos == std::string::npos) {
          sub_key = key.substr(pos);
          new_pos = key.size();
        } else {
          sub_key = key.substr(pos, new_pos - pos);
        }

        pos = new_pos + 1;
        node = &node->map[sub_key];
        node->me.set_root_name(sub_key);
      }

      node->me.merge(value);
    }

    Tree gen_tree() const {
      Tree tree = me;

      for (auto node : map) {
        tree << node.second.gen_tree();
      }

      return tree;
    }
  } tree;

  for (auto itr : absolute) {
    tree.add(itr.first, itr.second);
  }

  return tree.gen_tree();
}

} // namespace LioLi
