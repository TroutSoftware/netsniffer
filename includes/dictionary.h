
#ifndef dictionary_72abd77e
#define dictionary_72abd77e

// Snort includes

// System includes
#include <cstdint>
#include <map>
#include <string>
#include <variant>

// Local includes

// Global includes

// Debug includes

namespace Common {

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

} // namespace Common

#endif // dictionary_72abd77e
