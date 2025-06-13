// Snort includes
#include <cstdint> // This is needed here as protocols/apr.h is depending on it

// #include <log/messages.h>
#include <protocols/arp.h>
#include <protocols/packet.h>

// System includes
#include <condition_variable>
#include <thread>

// Global includes
#include <lioli_tree_generator.h>

// Local includes
#include "inspector.h"
#include "module.h"
#include "pegs.h"

// Debug includes

namespace arp_monitor {

namespace {
const uint8_t null_hw_adr[6] = {0, 0, 0, 0, 0, 0};
const uint8_t broadcast_hw_adr[6]{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

} // namespace

using TP = std::chrono::time_point<std::chrono::steady_clock>;

class Inspector::Worker {
  std::shared_ptr<Settings> settings;

  struct ReqEntry {
    TP request_time;
    snort::arp::EtherARP arp;
  };

  struct ReplyEntry {
    TP reply_time;
    snort::arp::EtherARP arp;
  };

  bool match(const ReqEntry &req, const ReplyEntry &reply) const;

  std::mutex worker_mutex; // Mutex for worker
  std::thread worker_thread;
  bool worker_running = false;
  bool worker_terminating = false;
  void worker_loop();
  std::condition_variable worker_cv;
  std::list<ReqEntry> req_list;
  std::list<ReplyEntry> reply_list;

  void log(ReqEntry &);

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

bool Inspector::Worker::match(const ReqEntry &req,
                              const ReplyEntry &reply) const {
  const uint32_t qt = *reinterpret_cast<const uint32_t *>(req.arp.arp_tpa);
  const uint32_t qs = req.arp.arp_spa32;
  const uint32_t yt = *reinterpret_cast<const uint32_t *>(reply.arp.arp_tpa);
  const uint32_t ys = reply.arp.arp_spa32;

  return qt == ys &&
         (qs == yt || (yt == ys && reply.arp.ea_hdr.ar_op == ARPOP_REQUEST));
}

void Inspector::Worker::got_request(const snort::arp::EtherARP &ah) {
  TP now = std::chrono::steady_clock::now();
  std::scoped_lock lock(worker_mutex);
  if (req_list.size() < settings->get_max_req_queue()) {
    req_list.emplace_front(now, ah);
    // If this was the first element, we need to wake the worker, so it can set
    // a timeout
    if (req_list.size() == 1) {
      worker_cv.notify_all();
    }
  } else {
    Pegs::s_peg_counts.arp_request_overflow++;
  }
}

void Inspector::Worker::got_reply(const snort::arp::EtherARP &ah) {
  TP now = std::chrono::steady_clock::now();
  std::scoped_lock lock(worker_mutex);

  if (req_list.size()) {
    // It is likely that a reply matches the last request we saw, in which case
    // we don't need to involve the worker
    if (match(req_list.front(), {now, ah})) {
      Pegs::s_peg_counts.arp_matches++;
      req_list.pop_front();
      return;
    }

    reply_list.emplace_front(now, ah);
    worker_cv.notify_all();
  } else {
    // There were no requests, so it is an orphan reply
    Pegs::s_peg_counts.arp_orphan_reply++;
  }
}

void Inspector::Worker::log(ReqEntry &req) {
  Pegs::s_peg_counts.arp_unmatched++;

  LioLi::Tree alert("alert");

  alert << "Arp missing reply";

  std::string tag = settings->get_missing_reply_alert_tag();
  if (tag.length()) {
    alert << LioLi::Tree("tag") << tag;
  }

  LioLi::Tree arp_req("unanswered_arp_req");
  const auto src_mac = std::to_array<const uint8_t>(req.arp.arp_sha);
  const auto src_ip = std::to_array<const uint8_t>(req.arp.arp_spa);
  arp_req << (LioLi::Tree("principal")
              << LioLi::TreeGenerators::format_MAC(src_mac)
              << LioLi::TreeGenerators::format_IPv4(src_ip));

  const auto dst_ip = std::to_array<const uint8_t>(req.arp.arp_tpa);
  arp_req << (LioLi::Tree("looking_for")
              << LioLi::TreeGenerators::format_IPv4(dst_ip));

  alert << arp_req;

  LioLi::Tree root("$");
  root << alert;

  settings->get_logger() << std::move(root);
}

void Inspector::Worker::worker_loop() {
  std::unique_lock lock(worker_mutex);
  bool just_one_more_turn = settings->get_testmode();

  while (!worker_terminating || just_one_more_turn) {
    // This will ensure that in testmode, we have one extra round in the loop to
    // report all answered requests
    if (worker_terminating && just_one_more_turn) {
      just_one_more_turn = false;
    }

    // Remove expired entries
    TP exp = std::chrono::steady_clock::now() -
             std::chrono::milliseconds(settings->get_timeout_ms());
    while (req_list.size() &&
           (req_list.back().request_time < exp || worker_terminating)) {
      log(req_list.back());
      req_list.pop_back();
    }

    // Match replies, we don't use the for(auto e:list) format as we are
    // modifying the lists inline
    for (auto reply = reply_list.begin(); reply != reply_list.end(); reply++) {
      for (auto request = req_list.rbegin(); request != req_list.rend();) {
        if (match(*request, *reply)) {
          Pegs::s_peg_counts.arp_matches++;
          Pegs::s_peg_counts.arp_late_match++;

          auto request_to_delete =
              (++request).base(); // request is a reverse iterator
          auto reply_to_delete = reply++;

          req_list.erase(request_to_delete);
          reply_list.erase(reply_to_delete);

          if (reply == reply_list.end())
            goto bail_double_for_loop;
        } else {
          request++;
        }
      }
    }
  bail_double_for_loop:

    Pegs::s_peg_counts.arp_orphan_reply += reply_list.size();
    reply_list.clear();

    if (req_list.size()) {
      worker_cv.wait_for(lock,
                         std::chrono::milliseconds(settings->get_timeout_ms()),
                         [this] { return worker_terminating; });
    } else {
      worker_cv.wait(lock,
                     [this] { return worker_terminating || req_list.size(); });
    }
  }
}

void Inspector::eval(snort::Packet *p) {
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
}

Inspector::Inspector(Module *module)
    : worker(std::make_unique<Worker>(module->get_settings())),
      settings(module->get_settings()) {}

Inspector::~Inspector() {}

snort::Inspector *Inspector::ctor(snort::Module *module) {
  return new Inspector(dynamic_cast<Module *>(module));
}

} // namespace arp_monitor
