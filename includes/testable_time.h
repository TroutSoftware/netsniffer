
#ifndef testable_time_e780753d
#define testable_time_e780753d

// Snort includes

// System includes
#include <chrono>

// Local includes

// Debug includes

namespace Common {
// Class that will give fake timestamps in testmode, and real when not in
// testmode
class TestableTime {

public:
  using Precision = std::chrono::nanoseconds;

  template <class T> static std::chrono::time_point<T, Precision> now(bool testmode) {
    if (testmode) {
      return std::chrono::floor<Precision>(std::chrono::time_point<T>());
    }

    return std::chrono::floor<Precision>(T::now());
  }
};
} // namespace Common
#endif // #ifndef testable_time_e780753d
