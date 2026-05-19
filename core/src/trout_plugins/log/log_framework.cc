
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Snort includes

// System includes
#include <map>
#include <ranges>

// Local includes
#include "../includes/log_framework.h"

// Debug includes

namespace LioLi {

std::shared_ptr<Serializer> &Serializer::get_null_obj() {
  class NullSerializer : public Serializer {

    bool is_binary() override { return false; }
    bool is_ready() override {
      return false;
    } // A null serializer is never ready

    class Context : public Serializer::Context {
      bool closed = false;

    public:
      std::string serialize(const Tree &&) override { return ""; }

      std::string close() override {
        closed = true;
        return "";
      }

      bool is_closed() override { return closed; }
    };

    std::shared_ptr<Serializer::Context> create_context() override {
      return std::make_shared<Context>();
    }

  public:
    NullSerializer() : Serializer("NullSerializer") {}
  };

  static std::shared_ptr<Serializer> null_serializer =
      std::make_shared<NullSerializer>();

  return null_serializer;
}

std::shared_ptr<Logger> &Logger::get_null_obj() {
  class NullLogger : public Logger {
    bool is_ready() override { return false; } // A null logger is never ready
    void operator<<(const Tree &&) override {}

  public:
    NullLogger() : Logger("NullLogger") {}
  };

  static std::shared_ptr<Logger> null_logger = std::make_shared<NullLogger>();

  return null_logger;
}

std::mutex LogDB::mutex;

std::map<std::string, std::shared_ptr<LogBase>> LogDB::db;

bool LogDB::register_obj(std::string name, std::shared_ptr<LogBase> sptr) {
  static std::once_flag register_flag;
  std::call_once(register_flag, []() { std::atexit(LogDB::shutdown_handler); });

  std::scoped_lock lock(mutex);
  return db.emplace(name, sptr).second;
}

void LogDB::shutdown_handler() {
  std::multimap<LogBase::Priority, std::shared_ptr<LogBase>> shutdown_queue;

  // Make a sorted version of the map we can walk without having the mutex
  // locked
  {
    std::scoped_lock lock(mutex);
    for (const auto &ptr : db | std::views::values) {
      shutdown_queue.insert({ptr->get_shutdown_priority(), ptr});
    }
  }

  // Tell everything to shutdown, mutex free and in priority orders)
  for (auto &ptr : shutdown_queue | std::views::values) {
    if (ptr)
      ptr->shutdown();
  }

  std::scoped_lock lock(mutex);

  // If the size changed during the shutdown, we have an issue
  assert(shutdown_queue.size() == db.size());

  // Empty the list so no one can retrieve shutdown elements anymore
  db.clear();
}

} // namespace LioLi
