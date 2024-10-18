
// Snort includes

// System includes

// Local includes
#include "log_framework.h"

namespace LioLi {

std::shared_ptr<LogStream> &LogStream::get_null_obj() {
  class NullLogStream : public LogStream {
    void set_binary_mode() override{};
    void operator<<(const std::string &&) override{};

  public:
    NullLogStream() : LogStream("NullLogStream") {}
  };

  static std::shared_ptr<LogStream> null_stream =
      std::make_shared<NullLogStream>();

  return null_stream;
}

std::shared_ptr<LogLioLiTree> &LogLioLiTree::get_null_obj() {
  class NullLogTree : public LogLioLiTree {
    void log(Tree &&) override {}

  public:
    NullLogTree() : LogLioLiTree("NullLogTree"){};
  };

  static std::shared_ptr<LogLioLiTree> null_tree =
      std::make_shared<NullLogTree>();
  return null_tree;
}

LogStream &LogLioLiTree::get_stream() {
  // Note: log_stream is atomic
  if (!log_stream.load()) {
    std::mutex mutex;
    std::scoped_lock lock(mutex);
    // LogDB::get will return null obj, and not a null_ptr, so it's safe to call
    log_stream = LogDB::get<LogStream>(log_stream_name.c_str());
  }
  return *log_stream.load().get();
}

std::mutex LogDB::mutex;
std::map<std::string, std::shared_ptr<LogBase>> LogDB::db;

bool LogDB::register_obj(std::string name, std::shared_ptr<LogBase> sptr) {
  std::scoped_lock lock(mutex);
  return db.emplace(name, sptr).second;
}

} // namespace LioLi
