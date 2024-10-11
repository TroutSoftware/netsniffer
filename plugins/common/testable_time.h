
#ifndef testable_time_e780753d
#define testable_time_e780753d

// Snort includes

// System includes
#include <chrono>

// Local includes

// Debug includes

// Class that will give fake timestamps in testmode, and real when not in
// testmode
class TestableTime {

public:
  template <class T> static std::chrono::time_point<T> now(bool testmode) {
    if (testmode) {
      return std::chrono::time_point<T>();
    }

    return T::now();
  }
};

#endif // #ifndef testable_time_e780753d
