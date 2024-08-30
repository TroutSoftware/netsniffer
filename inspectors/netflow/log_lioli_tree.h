#ifndef log_lioli_tree_9956cf27
#define log_lioli_tree_9956cf27

// Std logger interface for logging lioli::tree objects
#include "lioli.h"

namespace LioLi {

class LogLioLiTree {
public:
  virtual ~LogLioLiTree() = default;

  virtual void log(Tree &&) = 0;

  bool operator==(LogLioLiTree &rhs) { return (this == &rhs); }

  operator bool() const { return (this != &get_null_tree()); }

  static LogLioLiTree &get_null_tree() {
    static class NullLogTree : public LogLioLiTree {
      void log(Tree &&) override {}
    } null_tree;
    return null_tree;
  };
};

} // namespace LioLi

#endif // #ifdef log_lioli_tree_9956cf27
