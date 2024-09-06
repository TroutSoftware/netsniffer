#ifndef log_lioli_stream_77e07bbd
#define log_lioli_stream_77e07bbd

#include <string>

namespace LioLi {

class LogStream {
public:
  virtual ~LogStream() = default;

  virtual void set_binary_mode() = 0;

  virtual void operator<<(const std::string &tree) = 0;

  bool operator==(LogStream &rhs) { return (this == &rhs); }

  operator bool() const { return (this != &get_null_log_stream()); }

  static LogStream &get_null_log_stream() {
    static class NullLogStream : public LogStream {
      void set_binary_mode() override {};
      void operator<<(const std::string &) override {};
    } null_log;
    return null_log;
  };
};

} // namespace LioLi

#endif
