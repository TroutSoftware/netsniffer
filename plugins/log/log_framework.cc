
// Snort includes

// System includes

// Local includes
#include "log_framework.h"

namespace LioLi {

std::shared_ptr<Serializer> &Serializer::get_null_obj() {
  class NullSerializer : public Serializer {

    bool is_binary() override { return false; }

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
    bool had_data_loss(bool) override { return false; }
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
  std::scoped_lock lock(mutex);
  return db.emplace(name, sptr).second;
}

} // namespace LioLi
