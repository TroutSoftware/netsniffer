#ifndef trout_utils_baffe25a
#define trout_utils_baffe25a

// Snort includes

// System includes
#include <atomic>
#include <bit>
#include <cassert>
#include <random>

// Local includes

// Debug includes

namespace Common {

// Might be a pseudo-random on some systems
class Random {
  std::random_device rd;

public:
  // Returns random number between min and max (both min and max can be
  // returned)
  int random(int min, int max) {
    assert(min <= max);
    std::uniform_int_distribution<> distrib(min, max);
    return distrib(rd);
  }
};

// Helper function converting value to network order
template <class T> constexpr T to_network_order(T v) {
  if constexpr (std::endian::native == std::endian::big) {
    return v;
  } else if constexpr (std::endian::native == std::endian::little) {
    return std::byteswap(v);
  } else {
    static_assert(false, "Host endianess is not supported");
  }
}

// Helper class that allows to track a dirty state shared between objects
// without frequent syncronisation
class DirtyTracker {
  std::atomic_uint_fast32_t count =
      0; // We are fine with the counter looping around
  enum class State { dirty, not_dirty, armed };
  State state = State::dirty;

public:
  bool is_dirty() { return state == State::dirty; }

  operator bool() { return is_dirty(); }

  void clear_dirty() {
    if (state == State::dirty) {
      state = State::not_dirty;
    }
  }

  // Clears dirty state and waits for trigger
  void rearm() { state = State::armed; }

  void trigger() {
    if (state == State::armed) {
      count++; // Wraparound is fine, we just need values that aren't repeating
               // frequently
      state = State::dirty;
    }
  }

  void sync_to(DirtyTracker &master) {
    // It doesn't matter if master.count is updated after we have
    // detected that it is different, having the count be atomic makes this safe
    if (count != master.count) {
      count.store(master.count);
      state = State::dirty;
    }
  }
};

} // namespace Common
#endif // #ifndef trout_utils_baffe25a
