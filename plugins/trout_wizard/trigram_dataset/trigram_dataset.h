
#ifndef TRIGRAM_DATASET_H
#define TRIGRAM_DATASET_H

// System includes
#include <cstdint>
#include <vector>

struct TrigramSet {
  std::string protocol;
  std::uint32_t tgs;
};

extern std::vector<TrigramSet> trigram;

#endif // TRIGRAM_DATASET_H