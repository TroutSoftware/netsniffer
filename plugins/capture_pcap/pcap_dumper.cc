
// Snort includes
#include <framework/decode_data.h>
#include <protocols/packet.h>

// System includes
#include <cstring>    // For memcpy to queue raw packages
#include <queue>

// Local includes
#include "common.h"
#include "pcap_dumper.h"
#include "settings.h"

// Debug includes
#include <iostream>

namespace capture_pcap {

namespace {


}

std::string PcapDumper::gen_dump_file_name() {
    return "mkr_test.pcap";
}

PcapDumper::PcapDumper(std::string base_name, Module &module) : settings(module.get_settings()), pegs(module.get_peg_counts()), base_name(base_name) {
  // Start worker thread
  dlt = get_dlt();    // Note: This needs to happen from the main thread
  std::cout << "MKRTEST: Starting worker loop" << std::endl;   
  worker_thread = std::thread{&PcapDumper::worker_loop, this};
  std::cout << "MKRtEST: worker look joinable:" << worker_thread.joinable() << std::endl;
}

PcapDumper::~PcapDumper() {
  // Ask worker thread to terminate
  std::cout << "MKRTEST: Terminating worker loop" << std::endl;
  terminate = true;
  cv.notify_one();
  worker_thread.join();
}

PcapDumper::PackageBufferElement::PackageBufferElement(snort::Packet *p) : data(new uint8_t[p->pktlen]) {
  assert(data.get());
  
  pcaphdr.ts = p->pkth->ts;
  pcaphdr.caplen = p->pktlen;
  pcaphdr.len = p->pkth->pktlen;

  memcpy(data.get(), p->pkt, p->pktlen);
}

unsigned char *PcapDumper::PackageBufferElement::get_data() {
  return data.get();
}

size_t PcapDumper::PackageBufferElement::get_data_size() {
  return pcaphdr.caplen;
}

pcap_pkthdr *PcapDumper::PackageBufferElement::get_pkthdr() {
  return &pcaphdr;
}

void PcapDumper::queue_package(snort::Packet *p) {
  std::scoped_lock lock(mutex);
  queue.emplace(p); 
  cv.notify_one();
  std::cout << "MKRTEST: queue now has " << queue.size() << " elements" << std::endl;
}

void PcapDumper::worker_loop() {
  std::cout << "MKRTEST: worker_loop started, snaplen: " << settings->snaplen << std::endl;
  pcap_dumper_t *dumper = nullptr;    // Handle to the dump file
  pcap_t *dead = pcap_open_dead(dlt, settings->snaplen);
  size_t data_written = 0;

  assert(dead); // This is not expected to fail (i.e. something is wrong in the code if it happens)
  
  std::unique_lock lock(mutex);
  while(!terminate) {
    while(!queue.empty() && !terminate) {
      PackageBufferElement &front = queue.front();
      lock.unlock();  // We don't want to block while we deal with the filesystem and we are the only thread removing elements, so our front is good.
      
      if (!dumper) {
        std::string file_name = gen_dump_file_name();
        dumper = pcap_dump_open(dead, file_name.c_str());
        if (!dumper) {
          snort::ErrorMessage("ERROR: pcap reports \"%s\" when trying to open \"%s\" for writing",
                              pcap_geterr(dead), file_name.c_str());
          // In case of failure we just skip a package and continue
          lock.lock();
          queue.pop();
          continue;
        }
        data_written = 0;
      }

      // NOTE: pcap_dump doesn't have any return value, we assume all is good
      pcap_dump((unsigned char*)dumper, front.get_pkthdr(), front.get_data());
      data_written += front.get_data_size();
      pegs.pkg_written++;

      if (data_written > settings->rotate_limit) {
        pcap_dump_close(dumper);
        dumper = nullptr;
      }

      lock.lock();  // Retake the lock as we are going to manipulate queue
      queue.pop();
    }
    cv.wait(lock, [this]{return (terminate || !queue.empty());});
  };

  if (dumper) {
    pcap_dump_close(dumper);
    dumper = nullptr;
  }

  if (dead) {
    pcap_close(dead);
    dead = nullptr;
  }

  std::cout << "MKRTEST: worker_loop terminated" << std::endl;
}


} //namespace capture_pcap
