#ifndef pcap_dumper_a25c9fdf
#define pcap_dumper_a25c9fdf

// Snort includes


// System includes
#include <condition_variable>
#include <mutex>
#include <pcap/pcap.h>
#include <queue>
#include <string>

// Global includes

// Local includes
#include "module.h"

// Debug includes

namespace capture_pcap {

class PcapDumper {
  std::shared_ptr<Settings> settings;
  PegCounts &pegs;

  std::string base_name;

  class PackageBufferElement {
    std::unique_ptr<uint8_t[]> data;
    pcap_pkthdr pcaphdr;

  public:
    PackageBufferElement(snort::Packet *p);    
    PackageBufferElement(PackageBufferElement&& ) = delete;
    PackageBufferElement(PackageBufferElement& ) = delete;

    unsigned char *get_data();
    size_t get_data_size();
    pcap_pkthdr *get_pkthdr();
  };

  std::mutex mutex;  // Protects queue
  std::queue<PackageBufferElement> queue;

  // Worker thread controls
  std::thread worker_thread;
  std::condition_variable cv; // Used to enable worker to sleep when there
                              // aren't anything for it to do
  volatile bool terminate = false; // Set to true if worker loop should be terminated
  void worker_loop();         // Thread doing all the fun
  int dlt;                    // dlt to use

  std::string gen_dump_file_name(); // Creates the dump file name
  
public:
  PcapDumper(std::string base_name, Module &module);  // Creates a dumper with base_name as postfixed
  ~PcapDumper();

  void queue_package(snort::Packet *p); // Write p to the file
  
};

} // namespace capture_pcap
#endif // #ifndef pcap_dumper_a25c9fdf
