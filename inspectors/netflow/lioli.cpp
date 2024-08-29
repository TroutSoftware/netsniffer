

#include "lioli.h"

#include <cassert>

#include <iostream>

namespace LioLi {

// Helper functions for serializing
class Binary {
public:
  // Convert to format compatioble with GO varints
  static std::ostream &as_varint(std::ostream &os, uint64_t number) {
    // assert(number >= 0);
    do {
      uint8_t digit = number & 0b0111'1111;
      number >>= 7;
      if (number)
        digit |= 0b1000'0000;
      os << digit;
    } while (number);

    return os;
  }
};

Dictionary::Dictionary(uint16_t max_entries) : max_entries(max_entries) {}

void Dictionary::reset() { map.clear(); }

std::variant<Dictionary::index_t, Dictionary::Result>
Dictionary::find(const std::string &entry) {
  auto itr = map.find(entry);
  if (itr != map.end())
    return itr->second;
  if (map.size() < max_entries)
    return Result::not_found;
  return Result::overflow;
}

std::variant<Dictionary::index_t, Dictionary::Result>
Dictionary::add(const std::string &entry) {
  if (map.size() >= max_entries)
    return Result::overflow;
  if (!map.try_emplace(entry, map.size()).second)
    return Result::duplicate;
  return static_cast<index_t>(map.size() - 1);
}

void Tree::Node::set_end(size_t new_end) { end = new_end; }

void Tree::Node::append_child(const Node &node, size_t delta) {
  last_child_added = children.emplace_after(last_child_added, node);
  last_child_added->adjust(delta);
}

Tree::Node::Node(){};

Tree::Node::Node(std::string name) : my_name(name) {}

void Tree::Node::adjust(size_t delta) {
  start += delta;
  end += delta;

  for (auto &child : children) {
    child.adjust(delta);
  }
}

std::string Tree::Node::dump_tree(const std::string &raw,
                                  unsigned level) const {
  std::string output;
  for (unsigned i = level; i > 0; i--) {
    output += "-";
  }
  output += my_name + ": ";

  output += raw.substr(start, end - start);

  output += "\n";

  for (auto &child : children) {
    output += child.dump_tree(raw, level + 1);
  }
  return output;
}

std::string Tree::Node::dump_binary(Dictionary &dict, size_t delta) const {
  std::string output;

  if (!children.empty()) {
    output.append(2,
                  0); // Reserve 2 bytes at the beginning for string content
  }

  // Try to make a dictionary lookup
  auto dict_result = dict.find(my_name);

  if (std::holds_alternative<Dictionary::index_t>(dict_result)) {
    auto index = std::get<Dictionary::index_t>(dict_result);
    assert(0b0011'1111 >=
           index); // We can only encode 6 bit's - dict_result should have been
                   // negative if limit was reached

    output += static_cast<char>(index);
  } else {
    if (Dictionary::Result::not_found ==
        std::get<Dictionary::Result>(
            dict_result)) { // If dict has space but didn't find name, add it

      // Entry not found
      dict_result = dict.add(my_name);
      assert(std::holds_alternative<Dictionary::index_t>(
          dict_result)); // Logic error, we should be able to add to the dict
    }

    // Make full encode of our name
    auto name_length = my_name.size(); // Length of the name of this node

    assert(name_length <= 0b0011'1111'1111'1111); // We can't serialize names
                                                  // longer than 14 bits

    output += static_cast<char>(0b0100'0000 | (name_length & 0b0011'1111));
    output += static_cast<char>(name_length >> 6);

    output += my_name;
  }

  auto skip = start - delta; // How much of the raw string should be skipped
                             // before this node starts
  auto length = end - start; // Length of the raw string captured by this node
  if (skip <= 0b0000'0111 && length <= 0b0000'1111) {
    // 1 byte (3-bit start delta (x), 4 bit length (y) 0b0xxx yyyy
    output += static_cast<char>((skip << 4) | length);
  } else if (skip <= 0b0011'1111 && length <= 0b1111'1111) {
    // 2 bytes (6-bit start delta (x), 8 bit length (y) 0b10xx xxxx yyyy
    // yyyy
    output += static_cast<char>(0b1000'0000 | skip);
    output += static_cast<char>(length);
  } else {
    // 4 bytes (14-bit start delta (x), 16 bit length (y) 0b11xx xxxx xxxx
    // xxxx yyyy yyyy yyyy yyyy
    assert(skip <= 0b0011'1111'1111'1111 &&
           length <=
               0b1111'1111'1111'1111); // These are the max sizes we can encode
    // TODO: We probably want to fail gracefully here, e.g. consider
    // truncating data / child nodes

    output += static_cast<char>(0b1100'0000 | (0b0011'1111 & skip));
    output += static_cast<char>(skip >> 6);
    output += static_cast<char>(0b1111'1111 & length);
    output += static_cast<char>(length >> 8);
  }

  size_t new_start = start;

  for (auto &child : children) {
    output += child.dump_binary(dict, new_start);
    new_start = child.end;
  }

  if (!children.empty()) {
    auto length =
        output.size() - 2; // We don't include the size bytes in the length
    assert(length <= 0b0111'1111'1111'1111); // We only have 15 bits for the
                                             // length encoding
    output[0] = 0b1000'0000 | (length & 0b0111'1111);
    output[1] = length >> 7;
  }
  return output;
}

std::string raw; // The raw string (e.i. the string referenced by the tree)

Tree::Tree() {}
Tree::Tree(const std::string name) : me(name) {}
Tree &Tree::operator<<(const std::string &text) {
  raw += text;
  me.set_end(raw.size());

  return *this;
}

Tree &Tree::operator<<(const int number) {
  std::string sn = std::to_string(number);
  raw += sn;
  me.set_end(raw.size());

  return *this;
}

Tree &Tree::operator<<(const Tree &tree) {
  size_t delta = raw.size(); // Size of raw until now
  raw += tree.raw;
  me.set_end(raw.size());
  me.append_child(tree.me, delta);

  return *this;
}

std::string Tree::as_string() { return me.dump_tree(raw); }
/*
std::ostream &operator<<(std::ostream &os, const Tree &bf) {
  std::cout << "MKRTEST Dumping raw: " << bf.raw.size() << " bytes >" << bf.raw
<< ">" << std::endl; Binary::as_varint(os, bf.raw.size()); os << bf.raw;

  Dictionary dict(64);

  std::string tree = bf.me.dump_binary(dict, 0);

  std::cout << "MKRTEST Dumping tree: " << tree.size() << std::endl;
  Binary::as_varint(os, tree.size());
  os << tree;

  return os;
}
*/
LioLi::LioLi() {}

void LioLi::reset_dict() { dict.reset(); }

void LioLi::insert_header() { ss << "BILL" << '\x0' << '\x1'; }

void LioLi::insert_terminator() {
  Binary::as_varint(ss, 0xFFFF'FFFF'FFFF'FFFF);
}

std::ostream &operator<<(std::ostream &os, LioLi &out) {
  // std::cout << "MKRTEST: Dumping lioli (" << out.ss.str().size() << "
  // bytes)"<< std::endl;
  os << std::move(out.ss).str(); // Empty ss by moving its contents out
  // os << out.ss.str();
  // std::cout << "MKRTEST: After length is " << out.ss.str().size() << " bytes"
  // << std::endl;
  return os;
}

LioLi &operator<<(LioLi &ll, const Tree &bf) {
  // std::cout << "MKRTEST Dumping raw: " << bf.raw.size() << " bytes >" <<
  // bf.raw << ">" << std::endl;
  Binary::as_varint(ll.ss, bf.raw.size());
  ll.ss << bf.raw;

  std::string tree = bf.me.dump_binary(ll.dict, 0);
  // std::cout << "MKRTEST Dumping tree: " << tree.size() << std::endl;
  Binary::as_varint(ll.ss, tree.size());
  ll.ss << tree;

  return ll;
}

} // namespace LioLi
