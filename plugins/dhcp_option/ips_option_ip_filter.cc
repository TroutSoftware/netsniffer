
#include <string>

#include <framework/cursor.h>
#include <framework/module.h>
#include <hash/hash_key_operations.h>
#include <protocols/packet.h>

#include "ips_option_ip_filter.h"

namespace ip_filter {
namespace {

static const char *s_name = "ip_filter";
static const char *s_help = "Filters on ip address or mask of dhcp option";

static const snort::Parameter module_params[] = {
    {"~", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Identifies an ipv4 string for dhcp options ip_filter:123.456.789.012 "
     "(excact match) ip_filter:123.456.0.0/16 (match on first 16 bits) "
     "ip_filter:!123.456.789.0/24 (if not match on first 24 bits)"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

typedef uint32_t IpV4;

class IpMask {
  IpV4 ip = 0;            // Ip
  IpV4 mask = 0xFFFFFFFF; // Mask applied
  bool match = true;  // Set to True if matches means equal, false if not equal
  bool valid = false; // Set to true if object contain valid data

  uint8_t extract(std::string &input, std::string::size_type start,
                  std::string::size_type end, bool &success) {
    std::string number_string = input.substr(start, (end - start));
    auto value = std::stoul(number_string);
    success = value <= 0xFF;

    return value;
  }

public:
  IpMask() {}

  IpMask(std::string &input) {
    // We can parse strings like these:
    //  123.456.789.012
    //  !123.456.789.012
    //  123.456.789.012/16
    //  !123.456.789.012/24
    try {
      // Check for inital !
      match = !input.starts_with('!');

      std::string::size_type first = match ? 0 : 1;

      bool convertSucess = true;

      for (int i = 0; i < 4; i++) {
        auto last = input.find_first_not_of("0123456789", first);
        if (last == std::string::npos)
          last = input.size();
        ip <<= 8;
        ip |= extract(input, first, last, convertSucess);
        first = last + 1;
        // We don't expect a '.' at the end, important to test i != 3 before the
        // '.' !=... test, to prevent exception at the end
        if (!convertSucess || (i != 3 && '.' != input.at(last)))
          return;
      }

      // Check if we have anything after the ip (first is set to skip char after
      // last number above)
      if (--first < input.size()) {
        // We only expect a '/'
        if ('/' != input.at(first++))
          return;

        // If anything but numbers after this, it is a fault
        if (std::string::npos != input.find_first_not_of("0123456789", first))
          return;

        std::string number_string = input.substr(first, (input.size() - first));

        auto value = std::stoul(number_string);
        // A number greater than 31 doesn't make sense, as that would never
        // match anything
        if (value > 31)
          return;
        mask <<= 32 - value;
      }
      valid = true;
    } catch (...) {
      // Nothing to do, valid won't be set to true and object remains in invalid
      // state
    }
  }

  bool check(IpV4 test) {
    assert(valid);
    return ((ip & mask) == (test & mask)) == match;
  }

  IpV4 get_ip() const { return ip; }
  IpV4 get_mask() const { return mask; }
  bool get_match() const { return match; }
  bool is_valid() const { return valid; }

  bool operator==(const IpMask ip_mask) const {
    return (valid && ip == ip_mask.ip && mask == ip_mask.mask &&
            match == ip_mask.match) ||
           (!valid && !ip_mask.valid);
  }
};

class Module : public snort::Module {

  IpMask ip_mask;

  Module() : snort::Module(s_name, s_help, module_params) {}

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {

    if (val.is("~")) {

      std::string input = val.get_as_string();

      ip_mask = IpMask(input);

      return ip_mask.is_valid();
    }

    // fail if we didn't get something valid
    return false;
  }

  Usage get_usage() const override { return DETECT; }

public:
  static snort::Module *ctor() { return new Module(); }

  static void dtor(snort::Module *p) { delete p; }

  IpMask &get_mask() { return ip_mask; }
};

class IpsOption : public snort::IpsOption {

  IpMask ip_mask;

  IpsOption(Module &module)
      : snort::IpsOption(s_name), ip_mask(module.get_mask()) {}

  // Hash compare is used as a fast way to compare two instances of IpsOption
  uint32_t hash() const override {
    uint32_t a = snort::IpsOption::hash(), b = ip_mask.get_ip(),
             c = ip_mask.get_mask();

    mix(a, b, c);

    if (ip_mask.get_match()) {
      a += 100;
      mix(a, b, c);
    }

    finalize(a, b, c);

    return c;
  }

  // If hashes match a real comparison check is made
  bool operator==(const snort::IpsOption &ips) const override {
    return snort::IpsOption::operator==(ips) &&
           dynamic_cast<const IpsOption &>(ips).ip_mask == ip_mask;
  }

  EvalStatus eval(Cursor &c, snort::Packet * /*p*/) override {

    bool match =
        ip_mask.check(ntohl(*reinterpret_cast<const IpV4 *>(c.start())));

    // Move cursor forward
    c.add_pos(sizeof(IpV4));

    return match ? MATCH : NO_MATCH;
  }

  snort::CursorActionType get_cursor_type() const override {
    return snort::CAT_ADJUST;
  }

public:
  static snort::IpsOption *ctor(snort::Module *module, IpsInfo &) {
    assert(module);
    return new IpsOption(*dynamic_cast<Module *>(module));
  }

  static void dtor(snort::IpsOption *p) { delete p; }
};

} // namespace

const snort::IpsApi ips_option = {{
                                      PT_IPS_OPTION,
                                      sizeof(snort::IpsApi),
                                      IPSAPI_VERSION,
                                      0,
                                      API_RESERVED,
                                      API_OPTIONS,
                                      s_name,
                                      s_help,
                                      Module::ctor,
                                      Module::dtor,
                                  },
                                  snort::OPT_TYPE_DETECTION,
                                  0,
                                  PROTO_BIT__TCP,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  IpsOption::ctor,
                                  IpsOption::dtor,
                                  nullptr};

} // namespace ip_filter
