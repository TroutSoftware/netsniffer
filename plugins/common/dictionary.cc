
// Snort includes

// System includes

// Local includes
#include "dictionary.h"

// Global includes

// Debug includes

namespace Common {

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

} // namespace Common
