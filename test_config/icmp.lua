

logger_stdout = { serializer = 'serializer_txt' }

serializer_txt = { }

alert_lioli = { logger = 'logger_null',
                --testmode = true
                }

icmp_logger = {
  logger = "logger_stdout",
  testmode = true,
}

arp_monitor = {
  logger = "logger_null",
  testmode = true,
}

udp = {}
icmp4 = {}
--icmp4_ip = {}
stream_icmp = {}

--codec::icmp4 v0 static
--codec::icmp4_ip v0 static
--codec::icmp6 v0 static
--codec::icmp6_ip v0 static
--inspector::stream_icmp v0 static
--ips_option::icmp_id v0 static
--ips_option::icmp_seq v0 static

ips = {
  include = 'icmp.rules'
}
