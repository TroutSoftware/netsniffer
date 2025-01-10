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

// Debug includes

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
  template <typename T> static std::shared_ptr<T> get(const std::string &name) {
    return get<T>(name.c_str());
  }
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

class Serializer : public LogBase {

public:
  Serializer(const char *my_name) : LogBase(my_name) {}

  // There might be multiple serialization contexts in use at any given time or
  // sequentially, if serialization is in anyway state full, then we need  a
  // different object for each
  class Context {
  public:
    // Function that does the serialization, input is a LioLi tree and output is
    // a byte sequence, including any needed headers at the beginning, note
    // might return an empty object
    virtual std::string serialize(const Tree &&) = 0;

    // Terminate current context, returned byte sequence is any remaining
    // data/end marker of current context.  Context object is invalid after
    // this, except the is_closed() function.
    virtual std::string close() = 0;

    // Returns true if context is closed (invalid to call)
    virtual bool is_closed() = 0;

    virtual ~Context() = default;
  };

  // Return TRUE if the serialized output is binary, FALSE if it is text based
  virtual bool is_binary() = 0;

  virtual std::shared_ptr<Context> create_context() = 0;

  static std::shared_ptr<Serializer> &get_null_obj();
};

class Logger : public LogBase {

public:
  Logger(const char *my_name) : LogBase(my_name) {}

  // Must be non-blocking
  virtual void operator<<(const Tree &&tree) = 0;

  static std::shared_ptr<Logger> &get_null_obj();
};

} // namespace LioLi

#endif
