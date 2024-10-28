#ifndef lioli_h_693d75d2
#define lioli_h_693d75d2

// Snort includes

// System includes
#include <cstdint>
#include <forward_list>
#include <map>
#include <sstream>
#include <string>
#include <variant>

// Local includes

namespace LioLi {

class LioLi;

class Dictionary {
public:
  using index_t = uint16_t;

private:
  bool full = false;
  index_t max_entries;
  std::map<std::string, index_t> map;

public:
  Dictionary(index_t max_entries);
  enum class Result {
    not_found,
    overflow, // See interpretation in description for each function
    duplicate
  };

  // Reset content of dictionary
  void reset();

  // Returns index if found, or not_found when string isn't found and overflow
  // when string isn't found and can't be added
  std::variant<index_t, Result> find(const std::string &entry);

  // Returns index or overflow, overflow if dictionary is full, duplicate if
  // adding duplicate entry
  std::variant<index_t, Result> add(const std::string &entry);
};

class Tree {
  class Node {
    std::string my_name;
    size_t start = 0;
    size_t end = 0;
    std::forward_list<Node> children;
    std::forward_list<Node>::iterator last_child_added =
        children.before_begin();

    void adjust(size_t delta);

    void recalc_last_child() {
      auto next_child = children.before_begin();

      while (next_child != children.end()) {
        last_child_added = next_child;
        next_child++;
      }
    }

  public:
    Node();
    Node(std::string name);
    Node(const Node &);
    Node(Node &&src) = default;
    Node &operator=(Node &&other) = default;

    void set_end(size_t new_end);
    void append_child(const Node &node, size_t delta);

    std::string dump_string(const std::string &raw, unsigned level = 0) const;
    std::string dump_lorth(const std::string &raw, unsigned level = 0) const;
    std::string dump_binary(Dictionary &dict, size_t delta,
                            bool add_root_node = true) const;
  } me;

  std::string raw; // The raw string (e.i. the string referenced by the tree)

public:
  Tree();
  Tree(const std::string &name);
  Tree(const Tree &) = default;
  Tree(Tree &&src) = default;
  Tree &operator=(Tree &&other) = default;

  Tree &operator<<(const std::string &text);
  Tree &operator<<(const int number);
  Tree &operator<<(const Tree &tree);
  bool operator==(const Tree &tree) const;
  std::string as_string() const;
  std::string as_lorth();

  static bool is_valid_tree_name(const std::string &name);
  uint32_t hash() const { return raw.length(); } // Very simple hash function

  friend LioLi &operator<<(LioLi &ll, const Tree &bf);
  friend std::ostream &operator<<(std::ostream &os, const Tree &bf);
};

// A LioLi can contain multiple trees and be serialized in binary format
class LioLi {
  Dictionary dict = 64;
  std::stringstream ss;
  bool add_root_node = true;

public:
  LioLi();
  void reset_dict();
  void insert_header();
  void insert_terminator();
  std::string move_binary();
  void set_no_root_node() { add_root_node = false; }

  friend LioLi &operator<<(LioLi &ll, const Tree &bf);
  friend std::ostream &operator<<(std::ostream &os, LioLi &out);
};

} // namespace LioLi

#endif
