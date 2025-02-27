

serializer_bill = { bill_secret_sequence = '001122334455667788' }
--serializer_bill = { bill_secret_env = 'secret_bill'}

logger_file = { file_name = 'test.bill',
                serializer = 'serializer_bill' }
logger_null = { }
logger_stdout = { serializer = 'serializer_txt' }
logger_pipe = { serializer = 'serializer_txt',
                pipe_name = "test_pipe",
                restart_interval_s = 1 }

alert_lioli = { logger = 'logger_pipe' }

trout_netflow = { logger = 'logger_pipe'  }   


stream = {}
stream_tcp = {}
stream_udp = {}
http_inspect = {}

smnp = {}

include 'spells/ftp.lua'
include 'spells/ssh.lua'
include 'spells/http.lua'

wizard = {
    spells =  {
                ssh_spell,
                ftp_spell,
                http_spell,
              },
              
    hexes =  { { service = 'http2',
                 proto = 'tcp',
                 to_client = { '???|04 00 00 00 00 00|' },
                 to_server = { '|50 52 49 20 2a 20 48 54 54 50 2f 32 2e 30 0d 0a 0d 0a 53 4d 0d 0a 0d 0a|' }
               },
               { service = 'ssl',
                 proto = 'tcp',
                 to_server = { '|16 03|' },
                 to_client = { '|16 03|' }
               },
             },
             
}

binder = {
    { when = { ports = '160 161'}, use = { type = 'smnp' } },
    { use = {type = 'wizard'} }
}

-- daq = {
--     inputs = { 'enp0s3' },
-- }

ips = {
  include = 'live.rules'
}



trace.modules = {
    wizard = {
        all = 2,
    },
}

-- ips = {
--  include = 'test-local.rules'
-- }


