
logger_stdout = { serializer = 'serializer_txt' }

serializer_txt = { }

alert_talos = { }

icmp_logger = {
  logger = "logger_stdout",
  testmode = true,
}

ips = {
  include = 'test_local.rules'
}


