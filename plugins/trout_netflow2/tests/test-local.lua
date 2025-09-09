

stream = {}
stream_tcp = {}
stream_udp = {}

serializer_txt = {}
serializer_hex = {}
serializer_raw = { secret_sequence = "0022445566AABBCCDD" }
serializer_bill = { bill_secret_sequence = '000000000000000000' }

logger_tcp = { serializer = 'serializer_hex' ,
               output_ip = '127.0.0.1',
               output_port = 12345,
               alias = 'logger_tcp_hex'}


-- logger_tcp = { serializer = 'serializer_raw' ,
--                output_ip = '127.0.0.1',
--                output_port = 29999,
--                { alias = 'logger_tcp_txt',
--                  serializer = 'serializer_txt' ,
--                  output_ip = '127.0.0.1',
--                  output_port = 1234 },
--                { alias = 'logger_tcp_hex',
--                  serializer = 'serializer_hex' ,
--                  output_ip = '127.0.0.1',
--                  output_port = 12345 },
--                { alias = 'my_fancy_logger_name',
--                  serializer = 'serializer_bill' ,
--                  output_ip = '127.0.0.1',
--                  output_port = 1111,
--                  queue_max = 512,
--                  retry_interval_ms = 1000 },
-- }

trout_netflow2 = { logger = 'logger_tcp_hex' }

alert_lioli = { logger = 'logger_tcp_txt' }

icmp_logger = { logger = "my_fancy_logger_name" }




