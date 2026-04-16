#ifndef log_framework_77e07bbd
#define log_framework_77e07bbd

// Snort includes
#include <log/messages.h>

// System includes
#include <atomic>
#include <cstdlib>
#include <map>
#include <memory>
#include <mutex>
#include <string>

// Global includes
#include <trout_utils.h>

// Local includes
#include "lioli.h"

// Debug includes

namespace LioLi {

class LogBase {
private:
  std::string my_name = "unknown";

public:
  LogBase(const char *my_name) : my_name(my_name) {};
  virtual ~LogBase() = default;

  virtual void shutdown() {} // Do cleanup, will be called once
  const char *get_name() { return my_name.c_str(); }
  virtual bool is_ready() {
    return false;
  } // Returns true when component and dependencies are initialized

  enum class Priority {
    // Items listed first will be shutdown first
    ModuleWorker, // Module worker threads (depending on logger)
    Logger,       // Loggers (depending on Serializers)
    Serializer,   // Serialisers (doesn't depend on anything)
  };
  virtual Priority get_shutdown_priority() = 0;
};

// Concept to check something is publicly inheriting from LogBase
template <typename T>
concept BasedOn_LogBase = std::derived_from<T, LogBase>;

class LogDB {
  static std::mutex mutex;
  static std::map<std::string, std::shared_ptr<LogBase>> db;
  static bool register_obj(std::string, std::shared_ptr<LogBase>);
  static void shutdown_handler();

public:
  static bool register_instance(std::shared_ptr<LogBase> obj) {
    return register_obj(obj->get_name(), obj);
  }

  template <BasedOn_LogBase T, typename... Argtypes>
  static bool register_type(const char *name, Argtypes... args) {
    return register_instance(std::make_shared<T>(name, args...));
  };

  template <typename T> static std::shared_ptr<T> get(const std::string &name) {
    return get<T>(name.c_str());
  }

  static bool has_registration(const std::string &name) {
    return has_registration(name.c_str());
  }

  static bool has_registration(const char *name) {
    std::scoped_lock lock(mutex);
    return db.end() != db.find(name);
  }

  // get_unsafe might return a null shared_ptr
  template <typename T> static std::shared_ptr<T> get_unsafe(const char *name) {
    std::scoped_lock lock(mutex);
    auto lookup = db.find(name);

    if (lookup != db.end()) {
      auto sobj = dynamic_pointer_cast<T>(lookup->second);
      if (sobj) {
        return sobj;
      }

      snort::ErrorMessage(
          "ERR: (LogDB) log element >%s< requested with wrong type", name);
    } else {
      snort::WarningMessage("INFO: (LogDB) No registered log element of "
                            "correct type with name: >%s<\n",
                            name);
    }

    return nullptr;
  }

  // Get will always return a shared ptr to an object you can call
  template <typename T> static std::shared_ptr<T> get(const char *name) {
    auto r = get_unsafe<T>(name);

    if (r) {
      return r;
    }

    static_assert(
        requires {
          { T::get_null_obj() } -> std::same_as<std::shared_ptr<T> &>;
        }, "T needs a static get_null_obj() function returning a shared "
           "pointer to the T nullobj");

    return T::get_null_obj();
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

  operator bool() { return this != get_null_obj().get(); }

  Priority get_shutdown_priority() override { return Priority::Serializer; }
};

class Logger : public LogBase {
protected:
  // All loggers that might have dataloss, e.i. might drop data given to
  // it, either directly or indirectly must use the data loss tracker
  Common::DirtyTracker data_loss_tracker;

public:
  Logger(const char *my_name) : LogBase(my_name) {}

  // Must be non-blocking
  virtual void operator<<(const Tree &&tree) = 0;

  // Called by the framework at shutdown, ensures all data is flushed before
  // shutdown
  virtual void flush() {};

  //  Do not rely on actuall functions of the DataLossTracker
  using DataLossTracker = Common::DirtyTracker;
  bool has_lost_data(DataLossTracker &df) {
    df.clear_dirty();
    df.sync_to(data_loss_tracker);
    return df;
  }

  static std::shared_ptr<Logger> &get_null_obj();

  operator bool() { return this != get_null_obj().get(); }

  Priority get_shutdown_priority() override { return Priority::Logger; }
};

// Class a module can inherit e.g. a worker class from to get notified about
// being shutdown
class ModuleWorker : public LogBase {
public:
  ModuleWorker(const char *my_name) : LogBase(my_name) {}
  bool is_ready() override { return true; }

  Priority get_shutdown_priority() override { return Priority::ModuleWorker; }
};

} // namespace LioLi

#endif
