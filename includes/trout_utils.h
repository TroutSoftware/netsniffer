#ifndef trout_utils_baffe25a
#define trout_utils_baffe25a

// Snort includes

// System includes
#include <bit>
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

template <class T> constexpr T to_network_order(T v) {
  if constexpr (std::endian::native == std::endian::big) {
    return v;
  } else if constexpr (std::endian::native == std::endian::little) {
    return std::byteswap(v);
  } else {
    static_assert(false, "Host endianess is not supported");
  }
}

} // namespace Common
#endif // #ifndef trout_utils_baffe25a
