

--output_to_file = { file_name = 'my_output_file.txt' }
--output_to_pipe = { pipe_name = '/tmp/llpipe_17115325107265013479' }                                            
--output_to_pipe = { pipe_env = 'pipename' }
output_to_stdout = {}


serializer_bill = { bill_secret_sequence = '001122334455667788' }
--serializer_bill = { bill_secret_env = 'secret_bill'}

logger_file = { file_name = 'test.bill',
                serializer = 'serializer_bill' }
logger_null = { }
logger_stdout = { serializer = 'serializer_txt' }
logger_pipe = { serializer = 'serializer_txt',
                pipe_name = "test_pipe" }

alert_lioli = { logger = 'logger_null' }

trout_netflow = { logger = 'logger_stdout'  }   


stream = {}
stream_tcp = {}
http_inspect = {}

wizard = {
    spells = { { service = 'http', proto = 'tcp', to_server = {'GET'}, to_client = {'HTTP/'} } }
}

binder = {
    { when = { service = 'http' }, use = { type = 'http_inspect' } },
    { use = { type = 'wizard' } }
}

daq = {
     inputs = { '1' },
     modules = {
      { name = 'nfq', mode = 'inline', variables = {'queue_maxlen=8192', }, }
     }
}
