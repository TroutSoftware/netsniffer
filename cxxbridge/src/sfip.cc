#include "sfip/sf_ip.h"

namespace xsnort {


const snort::SfIp *from_str(const char *src) {
  auto ip = new snort::SfIp();
  ip->set(src);
  return ip;
}

}