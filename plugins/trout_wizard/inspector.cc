// Snort includes
#include <protocols/packet.h>
#include <stream/stream_splitter.h>

// System includes
#include <algorithm>
#include <mutex>
#include <optional>
#include <string>

// Global includes
#include <flow_data.h>
#include <lioli_path.h>

// Local includes
#include "inspector.h"
#include "module.h"

// Debug includes
#include <iostream>

namespace trout_wizard {
namespace {

class WizardFlow {
public:
  enum class BaseProtocol {
    tcp,
    udp,
    other,
  } base_protocol = BaseProtocol::other;

private:
  struct Cache {
    // Settings
    std::shared_ptr<Settings> settings;
    // Timestamp of first packet data is cached for
    struct timeval time_stamp = {0, 0};
    // Actual data cache
    std::string cache;

    Cache() {
      // Even we wanted to call reset here to resever cache space, we
      // can't as we can't be initialized with the settings in the construtor
    }

    bool empty() { return cache.empty(); }

    void reset() {
      time_stamp = {0, 0};
      cache.clear();
      cache.reserve(settings->split_size);
    }

    // Will return true if cache couldn't hold everything, offset will be
    // modified with amount added to cache
    bool append(const uint8_t *data, uint32_t data_length, uint32_t &offset) {
      assert(offset <=
             data_length); // We have a problem if the offset is past the end
      assert(settings); // Settings needs to be set before calling this function

      if (!settings->concatenate && !cache.empty()) {
        return true;
      }

      if (cache.size() >= settings->split_size) {
        return true;
      }

      uint32_t count = std::min(settings->split_size - (uint32_t)cache.size(),
                                data_length - offset);

      cache.append((char *)data + offset, count);

      offset += count;

      return offset < data_length;
    }
  } server_cache, client_cache;

  // Set on first data received
  std::optional<bool> client_first = {};
  std::optional<uint16_t> port = {};

  // Reset after each flush
  std::optional<bool> client_first_after_flush = {};

  unsigned id = 0;

  LioLi::Path root = {"$"};

  std::shared_ptr<Settings> settings;

public:
  // Get count for this flow
  unsigned flow_number() {
    static unsigned idc = 0;
    if (id == 0) {
      id = ++idc;
    }
    return id;
  }

  WizardFlow() { root << (LioLi::Tree("flow") << flow_number()); }

  ~WizardFlow() {
    flush();
    if (settings->tag.length() > 0) {
      root << (LioLi::Tree("tag") << settings->tag);
    }
    settings->get_logger() << std::move(root.to_tree());
  }

  void set_settings(std::shared_ptr<Settings> settings,
                    bool overwrite = false) {
    if (overwrite || !this->settings) {
      this->settings = settings;
      server_cache.settings = settings;
      client_cache.settings = settings;
    }
  }

  // Dumps stored data to the LioLi
  void flush() {
    if (server_cache.cache.empty() && client_cache.cache.empty()) {
      return;
    }
    LioLi::Tree chunk("chunk");

    if (client_first_after_flush.has_value()) {
      chunk << (LioLi::Tree("first_from")
                << (client_first_after_flush.value() ? "client" : "server"));
    }

    if (!server_cache.empty()) {
      LioLi::Tree server("server");

      server << (LioLi::Tree("time")
                 << server_cache.time_stamp.tv_sec << "."
                 << std::format("{:06}", server_cache.time_stamp.tv_usec));

      server << (LioLi::Tree("length") << server_cache.cache.size());
      server << (LioLi::Tree("data") << std::move(server_cache.cache));

      chunk << server;

      server_cache.reset();
    }

    if (!client_cache.empty()) {
      LioLi::Tree client("client");

      client << (LioLi::Tree("time")
                 << client_cache.time_stamp.tv_sec << "."
                 << std::format("{:06}", client_cache.time_stamp.tv_usec));

      client << (LioLi::Tree("length") << client_cache.cache.size());
      client << (LioLi::Tree("data") << std::move(client_cache.cache));

      chunk << client;

      client_cache.reset();
    }

    root << (LioLi::Path("#Chunks") << chunk);

    client_first_after_flush.reset();
  }

  void process(bool from_client, snort::Packet *p, const uint8_t *data,
               uint32_t data_length) {
    assert(p);

    bool is_ip = p->has_ip();

    if (!settings->pack_data && ((from_client && !server_cache.empty()) ||
                                 (!from_client && !client_cache.empty()))) {
      flush();
    }

    // TODO: Change base_protocol to std::optional?
    if (BaseProtocol::other == base_protocol) {
      if (is_ip) {
        if (p->is_tcp()) {
          base_protocol = BaseProtocol::tcp;
          root << (LioLi::Tree("protocol") << "TCP");
        } else if (p->is_udp()) {
          base_protocol = BaseProtocol::udp;
          root << (LioLi::Tree("protocol") << "UDP");
        }
      }
    }

    if (!port.has_value() && (BaseProtocol::tcp == base_protocol ||
                              BaseProtocol::udp == base_protocol)) {
      port = (p->is_from_server() ? p->ptrs.sp : p->ptrs.dp);
      root << (LioLi::Tree("port") << port.value());
    }

    if (!client_first.has_value()) {
      client_first = from_client;
      root << (LioLi::Tree("initiator")
               << (client_first ? "client" : "server"));
    }

    // Process the data
    uint32_t offset = 0;
    while (offset < data_length) {
      if (!client_first_after_flush.has_value()) {
        client_first_after_flush = from_client;
      }

      if (from_client) {
        if (client_cache.empty() && p->pkth) {
          client_cache.time_stamp = p->pkth->ts;
        }
        if (client_cache.append(data, data_length, offset)) {
          flush();
        }
      } else /* Must be from server */ {
        if (server_cache.empty() && p->pkth) {
          server_cache.time_stamp = p->pkth->ts;
        }
        if (server_cache.append(data, data_length, offset)) {
          flush();
        }
      }
    }
  }
};

using FlowData = Common::FlowData<WizardFlow>;

void dump_pkt(bool from_client, snort::Packet *p, const uint8_t *data,
              uint32_t data_length, std::shared_ptr<Settings> settings) {
  assert(p);

  FlowData *flow_data = (p->flow) ? FlowData::get_from_flow(p->flow) : nullptr;

  if (flow_data) {

    flow_data->set_settings(settings);

    flow_data->process(from_client, p, data, data_length);
  } else {
    snort::WarningMessage("WARNING: trout_wizard unable to parse packet due to "
                          "missing flow, check your configuration");
  }
}

} // namespace

class Splitter : public snort::StreamSplitter {
  std::shared_ptr<Settings> settings;

  Status scan(snort::Packet *p,
              const uint8_t *data, // in order segment data as it arrives
              uint32_t len,        // length of data
              uint32_t /*flags*/,  // packet flags indicating direction of data
              uint32_t * /*fp*/    // flush point (offset) relative to data
              ) override {

    dump_pkt(to_server(), p, data, len, settings);

    return SEARCH;
  }

  bool is_paf() override { return true; }

  unsigned max(snort::Flow *) override { return 32000; }

public:
  Splitter(std::shared_ptr<Settings> settings, bool c2s)
      : StreamSplitter(c2s), settings(settings) {}
};

void Inspector::eval(snort::Packet *p) {

  dump_pkt(p->is_from_client(), p, p->data, p->dsize, module.get_settings());
}

Inspector::~Inspector() {}

snort::StreamSplitter *Inspector::get_splitter(bool c2s) {
  return new Splitter(module.get_settings(), c2s);
}

snort::Inspector *Inspector::ctor(snort::Module *module) {
  return new Inspector(*dynamic_cast<Module *>(module));
}

void Inspector::dtor(snort::Inspector *p) {
  delete dynamic_cast<Inspector *>(p);
}

} // namespace trout_wizard
