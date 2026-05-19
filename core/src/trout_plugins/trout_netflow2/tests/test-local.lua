

stream = {}
--stream_tcp = {}
stream_udp = {}

stream = {}
stream_tcp = {}
stream_udp = {}

serializer_hex = {}
serializer_raw = { secret_sequence = "0022445566AABBCCDD" }

logger_file = { serializer = 'serializer_hex',
                file_name = 'output.hex'}

--logger_stdout = { serializer = 'serializer_txt'}

serializer_txt = {}
serializer_hex = {}
serializer_raw = { secret_sequence = "0022445566AABBCCDD" }
serializer_bill = { bill_secret_sequence = '000000000000000000' }

serializer_filter = { alias = 'filter_txt',
                      serializer = 'serializer_txt',
                      stream_prefix = "THIS IS BEGINNING OF TEXT\13\10",
                      stream_postfix = "end of transmission\13\10",
                      tree_delimiter = "<->",
                      {
                        alias = 'filter_hex',
                        serializer = 'serializer_hex' ,
                        stream_prefix = "This is a HEX transmission:\13\10",
                      },
                    }


logger_tcp =  { serializer = 'filter_txt' ,
                output_ip = '127.0.0.1',
                output_port = 123,
                { alias = 'logger_tcp_hex',
                  serializer = 'filter_hex' ,
                  output_ip = '127.0.0.1',
                  output_port = 234,
                },
              }

alert_lioli = { logger = 'logger_file' }
trout_netflow2 = { logger = 'logger_file',
                   flush_interval_ms = 500 }



-- logger_tcp = { serializer = 'filter_hex' ,
--               output_ip = '127.0.0.1',
--               output_port = 12345,
--               alias = 'logger_tcp_raw'}





logger_stdout = { serializer = 'filter-txt'}

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

-- trout_netflow2 = { logger = 'logger_file',
--                   flush_interval_ms = 500 }


--alert_lioli = { logger = 'logger_stdout' }

-- icmp_logger = { logger = "my_fancy_logger_name" }


-------------------


-- http_inspect = {}
dns = {}
-- appid = {
--  app_detector_dir = "plugins/trout_netflow2/tests/snort-openappid"
-- }

--wizard = {
--   spells = { { service = 'http', proto = 'tcp', to_server = {'GET'}, to_client = { 'HTTP' } } }

--}

binder = {
-- {when = {ports = '53'}, use = {  type = 'dns' } },
--   {when = {ports = '53'}, use = { type = 'dns' } },
--  {when = {service = 'dns'}, use = {type = 'dns' } },
--  {use = { type = 'wizard' }},
  {use = { type = 'dns' }},
}

-- include 'test_config/snort_defaults.lua'
-- include 'p/snort3-3.7.2.0/lua/snort_defaults.lua'

-- wizard = default_wizard

-- wizard = {
--    spells = { { service = 'http', proto = 'tcp', to_server = {'GET'}, to_client = {'HTTP/'} } },
--    spells = { { service = 'http', proto = 'tcp', to_server = {'GET'}, to_client = {'HTTPS/'} } }
-- }

-- binder = {
--    { when = { service = 'http' }, use = { type = 'http_inspect' } },
--    { use = { type = 'wizard' } }
-- }

local_rules =
[[
log dns (
  msg: "This is DNS";


  sid: 3002;
)
]]

-- service: "dns";
--  appid: dns;

ips = {
--  include = 'lua.rules'
  rules = local_rules,
}





