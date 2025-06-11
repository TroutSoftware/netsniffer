// Snort includes
#include <cstdint> // This is needed here as protocols/apr.h is depending on it

// #include <log/messages.h>
#include <protocols/arp.h>
#include <protocols/packet.h>

// System includes
#include <condition_variable>
#include <thread>

// Global includes

// Local includes
#include "inspector.h"
#include "module.h"
#include "pegs.h"

// Debug includes
#include <iostream>

namespace arp_monitor {

#if 0
namespace snort
{
namespace arp
{

struct ARPHdr
{
    uint16_t ar_hrd;       /* format of hardware address   */
    uint16_t ar_pro;       /* format of protocol address   */
    uint8_t ar_hln;        /* length of hardware address   */
    uint8_t ar_pln;        /* length of protocol address   */
    uint16_t ar_op;        /* ARP opcode (command)         */
};

struct EtherARP
{
    ARPHdr ea_hdr;      /* fixed-size header */
    uint8_t arp_sha[6];    /* sender hardware address */
    union
    {
        uint8_t arp_spa[4];    /* sender protocol address */
        uint32_t arp_spa32;
    };
    uint8_t arp_tha[6];    /* target hardware address */
    uint8_t arp_tpa[4];    /* target protocol address */
} __attribute__((__packed__));

constexpr uint16_t ETHERARP_HDR_LEN = 28; /*  sizeof EtherARP != 28 */

} // namespace arp
} // namespace snort

#endif

/*
void dump_to_stdout(uint8_t *data, uint16_t size) {
    int r = 0;
    for (int i = 0 ; i < size; i++) {
      std::cout << std::format("{:02x} ", data[i]);
      if( ++r >= 16 ) {
        std::cout << "\n";
        r = 0;
      }
    }
    std::cout << std::endl;
}
*/

namespace {
const uint8_t null_hw_adr[6] = {0, 0, 0, 0, 0, 0};
const uint8_t broadcast_hw_adr[6]{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

} // namespace

using TP = std::chrono::time_point<std::chrono::steady_clock>;

class Inspector::Worker {
  std::shared_ptr<Settings> settings;

  struct ReqEntry {
    TP request_time;
    snort::arp::EtherARP request;
  };

  struct ReplyEntry {
    TP reply_time;
    snort::arp::EtherARP reply;
  };

  std::mutex worker_mutex; // Mutex for worker
  std::thread worker_thread;
  bool worker_running = false;
  bool worker_terminating = false;
  void worker_loop();
  std::condition_variable worker_cv;
  std::list<ReqEntry> req_list;
  std::list<ReplyEntry> reply_list;

public:
  Worker(std::shared_ptr<Settings> settings);
  ~Worker();

  void start();
  void stop();

  void got_request(const snort::arp::EtherARP &ah);
  void got_reply(const snort::arp::EtherARP &ah);
};

Inspector::Worker::Worker(std::shared_ptr<Settings> settings)
    : settings(settings) {
  start();
}

Inspector::Worker::~Worker() { stop(); }

void Inspector::Worker::start() {
  std::scoped_lock lock(worker_mutex);
  assert(!worker_terminating); // We currently don't handle restarts
  if (!worker_running) {
    worker_thread = std::thread{&Inspector::Worker::worker_loop, this};
    worker_running = true;
  }
}

void Inspector::Worker::stop() {
  {
    std::scoped_lock lock(worker_mutex);
    if (worker_running) {
      worker_terminating = true;
      worker_cv.notify_all();
    }
  }
  worker_thread.join();
}

void Inspector::Worker::got_request(const snort::arp::EtherARP &ah) {
  TP now = std::chrono::steady_clock::now();
  std::scoped_lock lock(worker_mutex);
  if (req_list.size() < settings->get_max_req_queue()) {
    req_list.emplace_front(now, ah);
  } else {
    Pegs::s_peg_counts.arp_request_overflow++;
  }
  worker_cv.notify_all();
}

void Inspector::Worker::got_reply(const snort::arp::EtherARP &ah) {
  TP now = std::chrono::steady_clock::now();
  std::scoped_lock lock(worker_mutex);
  reply_list.emplace_front(now, ah);
  worker_cv.notify_all();
}

void Inspector::Worker::worker_loop() {
  std::unique_lock lock(worker_mutex);

  while (!worker_terminating) {

    worker_cv.wait(lock);
  }
}

/*
struct Inspector::ReqEntry {
  TP request_time;
  snort::arp::EtherARP request;
};

bool Inspector::remove_entries(const snort::arp::EtherARP *ah) {
  // TODO: Move to worker thread
  std::scoped_lock lock(req_list_mutex);
  for(auto e: req_list) {


  }

  return false;
}
*/
void Inspector::eval(snort::Packet *p) {
  // std::cout << "MKRTEST: ARP Package:" << std::endl;

  // If we don't get arp, then something is wrong
  assert(p && p->proto_bits & PROTO_BIT__ARP);

  Pegs::s_peg_counts.arp_packets++;

  const snort::arp::EtherARP *ah = snort::layer::get_arp_layer(p);

  if (!ah) {
    // TODO: Report no arp layer - not sure if this should be an assert (i.e. if
    // it is expected to happen or not)
    return;
  }

  switch (ntohs(ah->ea_hdr.ar_op)) {
  case ARPOP_REQUEST:
    // A request to one self, is the same as an anouncement
    // TODO: Check it is a broadcast on the ethernet level
    if (memcmp(ah->arp_tpa, ah->arp_spa, 4)) {
      // New requests are queued
      Pegs::s_peg_counts.arp_requests++;

      worker->got_request(*ah);
      /*
            if (settings->get_max_req_queue() >= req_list.size() ) {
              Pegs::s_peg_counts.arp_request_overflow++;
              return;
            }

            std::scoped_lock lock(req_list_mutex);
            TP now = std::chrono::steady_clock::now();
            req_list.emplace_front(now, *ah);
      */
    } else {
      Pegs::s_peg_counts.arp_announcements++;

      if (settings->get_announcement_is_reply()) {
        worker->got_reply(*ah);
      }
    }
    break;
  case ARPOP_REPLY:
    Pegs::s_peg_counts.arp_replies++;
    worker->got_reply(*ah);
    // remove_entries(ah);
    break;
  case ARPOP_RREQUEST:
    Pegs::s_peg_counts.arp_rrequests++;
    break;
  case ARPOP_RREPLY:
    Pegs::s_peg_counts.arp_rreplies++;
    break;
  default:
    Pegs::s_peg_counts.arp_unknown_command++;
  }

  //    PegCount arp_requests = 0;
  //    PegCount arp_replies = 0;
  //    PegCount arp_id_broadcasts = 0;

  if (!ah) {
    std::cout << "MKRTEST: NO ARP LAYER" << std::endl;
    return;
  }
}

Inspector::Inspector(Module *module)
    : worker(std::make_unique<Worker>(module->get_settings())),
      settings(module->get_settings()) {}

Inspector::~Inspector() {}

snort::Inspector *Inspector::ctor(snort::Module *module) {
  return new Inspector(dynamic_cast<Module *>(module));
}

} // namespace arp_monitor
