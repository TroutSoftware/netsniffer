

--output_to_file = { file_name = 'my_output_file.txt' }
--output_to_pipe = { pipe_name = '/tmp/llpipe_1863275496415381555' }
--output_to_pipe = { pipe_env = 'pipename' }
--output_to_stdout = {}

--log_lorth = { output = 'output_to_stdout' }
--log_bill = { output = 'output_to_pipe' }
--log_txt = { output = 'output_to_stdout' }

logger_null = {}
logger_stdout = { serializer = 'serializer_txt' }
serializer_txt = { }

alert_lioli = { logger = 'logger_stdout' }

trout_netflow = { logger = 'logger_null' } 

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

ips = {
  include = 'test-local.rules'
}
