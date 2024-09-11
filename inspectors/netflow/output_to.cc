
// Snort includes
#include <log/messages.h>
#include <managers/inspector_manager.h>

// System includes

// Local includes
#include "output_to.h"

namespace LioLi {

std::shared_ptr<LogStream> LogStream::get_null_log_stream() {
  class NullLogStream : public LogStream {
    void set_binary_mode() override {};
    void operator<<(const std::string &&) override {};
  };

  static std::shared_ptr<LogStream> null_log =
      std::make_shared<NullLogStream>();

  return null_log;
}

void LogStreamHelper::set_name(std::string &name) {
  std::scoped_lock lock(mutex);

  assert(!name.empty()); // We need a name
  assert(stream_name.empty() ||
         name == stream_name); // We do not handle name changes

  stream_name = name;
};

LogStream &LogStreamHelper::get() {
  if (!log_stream.load()) {
    std::scoped_lock lock(mutex);

    // Handle the race where multiple threads tries to enter at the same time
    if (!log_stream.load()) {

      if (stream_name.empty()) {
        snort::ErrorMessage("ERROR: No stream name set to logger\n");

        return *LioLi::LogStream::get_null_log_stream();
      }

      auto mp = snort::InspectorManager::get_inspector(
          stream_name.c_str(), snort::Module::GLOBAL, snort::IT_PASSIVE);
      auto dyn_stream = dynamic_cast<LioLi::LogStream *>(mp);

      if (!dyn_stream) {
        snort::ErrorMessage("ERROR: No valid stream name set to logger\n");

        return *LioLi::LogStream::get_null_log_stream();
      }

      log_stream = dyn_stream->get_log_stream();
    }
  }

  return *log_stream.load();
}

} // namespace LioLi
