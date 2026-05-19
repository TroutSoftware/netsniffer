#ifndef know_hash_46b5d599
#define know_hash_46b5d599

////////////////////////////////////////////////////////////////////////
//
// KnownHash stores a bitmap from a (hash) value, and determines if it
// has been likely seen before, based on the Bloom filter pattern
//
////////////////////////////////////////////////////////////////////////

// Snort includes

// System includes
#include <array>

// Global includes

// Local includes

// Debug includes

namespace trout::discovery {

template <typename T> class KnownHash {
  static constexpr unsigned triad_count =
      1 + ((sizeof(T) * 8) / 3); // The max number of triads we need

  std::array<uint8_t, triad_count>
      bits; // We need one 8-bit byte for each 3 bits in the input

public:
  KnownHash() {
    // Init the bits array to zero
    clear();
  }

  void clear() {
    for (unsigned i = 0; i < triad_count; i++) {
      bits[i] = 0;
    }
  }
  // Returns false if we are sure we have not seen the hash
  bool has(T hash) {
    for (auto &triad : bits) {
      // Find the bit for the current triad
      uint8_t triad_value = 1 << (hash & 0b111);
      // Check if the bit is unset, note: binary and
      if (!(triad & triad_value)) {
        // If bit isn't set, we know we haven't seen it
        return false;
      }

      // go to the next triad
      hash >>= 3;
    }

    // All bits must have been set
    return true;
  }

  // Returns false if we are sure we have not seen the hash, otherwise
  // we add it
  bool has_and_set(T hash) {
    // We assume we have seen it
    bool seen = true;
    for (auto &triad : bits) {
      // Find the bit for the current triad
      uint8_t triad_value = 1 << (hash & 0b111);
      // Check if the bit is unset, note: binary and
      if (!(triad & triad_value)) {
        // If bit isn't set, we know we haven't seen it
        seen = false;
        // Set it
        triad |= triad_value;
      }

      // go to the next triad
      hash >>= 3;
    }

    return seen;
  }
};
}; // namespace trout::discovery

#endif // #ifndef know_hash_46b5d599
