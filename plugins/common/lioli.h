#ifndef lioli_693d75d2
#define lioli_693d75d2

// Snort includes

// System includes
#include <cassert>
#include <cstdint>
#include <forward_list>
#include <sstream>
#include <string>
#include <vector>

// Local includes

namespace LioLi {

class LioLi;

// A tree is a tree of nodes, even you can build a tree by adding one
// tree to another, the result does not consists of the two trees.
// A tree is a self contained entity, it has a single string with all
// the data it contains, and a node tree that names specific substrings
// of the main string in a tree structure
class Tree {
  class Node {
    std::string my_name;
    size_t start = 0;
    size_t end = 0; // (end - start) = length of data
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
    Node(Node &&src);
    Node &operator=(Node &&other) = default;
    virtual ~Node() = default;

    void set_end(size_t new_end);
    void add_as_child(const Node &node);
    void add_as_child(Node &&node);
    void append(const Node &node);
    void append(Node &&node);

    void set_name(const std::string &new_name) { my_name = new_name; }
    const std::string &get_name() const { return my_name; }

    std::string dump_string(const std::string &raw, unsigned level = 0) const;
    std::string dump_lorth(const std::string &raw, unsigned level = 0) const;
    std::string dump_python(const std::string &raw, unsigned level = 0) const;
    std::string dump_binary(size_t delta, bool add_root_node) const;

    // For debug/test
    bool is_valid(size_t start,
                  size_t end) const; // Will validate that node tree is between
                                     // start and end (length = end-start)
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
  Tree &operator<<(Tree &&tree);

  void merge(const Tree &tree, bool node_merge = false);
  void merge(Tree &&tree, bool node_merge = false);

  bool operator==(const Tree &tree) const;
  bool operator!=(const Tree &tree) const { return !(*this == tree); }

  void set_root_name(const std::string &new_name) { me.set_name(new_name); }
  const std::string &get_root_name() const { return me.get_name(); }
  std::string as_string() const;
  std::string as_lorth() const;
  std::string as_python() const;

  uint32_t hash() const {
    return raw.length();
  } // Very fast and simple hash function

  // For Debug
  bool is_valid() const; // Checks if the tree is valid

  // Friend functions
  friend LioLi &operator<<(LioLi &ll, const Tree &bf);
  friend std::ostream &operator<<(std::ostream &os, const Tree &bf);
};

// A LioLi can contain multiple trees and be serialized in binary format
class LioLi {
  std::stringstream ss;
  std::vector<uint8_t> secret;
  bool add_root_node = true;

public:
  LioLi();
  void insert_header();
  void insert_terminator();

  size_t length(); // Get the currently stored length
  std::string move_binary();
  void set_no_root_node() { add_root_node = false; }
  void set_secret(std::vector<uint8_t> &secret) {
    assert(secret.size() == 9); // There are exactly 9 bytes in a secret
    this->secret = secret;
  }

  friend LioLi &operator<<(LioLi &ll, const Tree &bf);
  friend std::ostream &operator<<(std::ostream &os, LioLi &out);
};

} // namespace LioLi

#endif
