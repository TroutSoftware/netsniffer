

--output_to_file = { file_name = 'my_output_file.txt' }
--output_to_pipe = { pipe_name = '/tmp/llpipe_17115325107265013479' }                                            
--output_to_pipe = { pipe_env = 'pipename' }
--output_to_stdout = {}


serializer_bill = { bill_secret_sequence = '001122334455667788' }
--serializer_bill = { bill_secret_env = 'secret_bill'}

logger_file = { file_name = 'test.bill',
                serializer = 'serializer_bill' }
logger_null = { }
logger_stdout = { serializer = 'serializer_txt' }
logger_pipe = { serializer = 'serializer_txt',
                pipe_name = "test_pipe",
                restart_interval_s = 1 }

alert_lioli = { logger = 'logger_null' }

trout_netflow = { logger = 'logger_pipe'  }   


stream = {}
stream_tcp = {}
http_inspect = {}


wizard = {
    spells = { { 
                 service = 'ftp',
                 proto = 'tcp',

                 to_client = { '220' },

               },
               { service = 'ssh',
                 proto = 'tcp',
                 to_server = { 'SSH-' },
                 to_client = { 'SSH-' }
               },
             }
}

binder = {    
    { use = { type = 'wizard' } }
}

daq = {
     inputs = { 'enp0s3' },
}

-- ips = {
--  include = 'live.rules'
-- }

