#ifndef log_framework_77e07bbd
#define log_framework_77e07bbd

// Snort includes
#include <log/messages.h>

// System includes
#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <string>

// Local includes
#include "lioli.h"

namespace LioLi {

class LogBase {
private:
  const char *my_name = "unknown";

public:
  LogBase(const char *my_name) : my_name(my_name){};
  virtual ~LogBase() = default;

  const char *get_name() { return my_name; }
};

class LogDB {
  static std::mutex mutex;
  static std::map<std::string, std::shared_ptr<LogBase>> db;
  static bool register_obj(std::string, std::shared_ptr<LogBase>);

public:
  template <typename T> static void register_type() {
    auto obj = std::make_shared<T>();

    register_obj(obj->get_name(), obj);
  };

  template <typename T> static std::shared_ptr<T> get(const char *name) {
    std::scoped_lock lock(mutex);
    auto lookup = db.find(name);

    if (lookup != db.end()) {
      auto sobj = dynamic_pointer_cast<T>(lookup->second);
      if (sobj) {
        return sobj;
      }
    }

    snort::ErrorMessage("ERROR: (LogDB) No registered log element of correct "
                        "type with name: %s\n",
                        name);

    return dynamic_pointer_cast<T>(T::get_null_obj());
  }
};

class LogStream : public LogBase {
public:
  LogStream(const char *my_name) : LogBase(my_name) {}

  // Virtual functions
  virtual void set_binary_mode() = 0;

  virtual void operator<<(const std::string &&tree) = 0;

  // Non virtual functions
  bool operator==(LogStream &rhs) { return (this == &rhs); }

  operator bool() const { return (this != get_null_obj().get()); }

  static std::shared_ptr<LogStream> &get_null_obj();
};

class LogLioLiTree : public LogBase {
  std::string log_stream_name;
  std::atomic<std::shared_ptr<LogStream>> log_stream;

protected:
  LogStream &get_stream();

public:
  LogLioLiTree(const char *my_name) : LogBase(my_name) {}

  virtual void log(Tree &&) = 0;

  bool operator==(LogLioLiTree &rhs) { return (this == &rhs); }

  operator bool() const { return (this != get_null_obj().get()); }

  void set_log_stream_name(const char *name) { log_stream_name = name; }

  static std::shared_ptr<LogLioLiTree> &get_null_obj();
};

} // namespace LioLi

#endif
