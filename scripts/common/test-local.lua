

--output_to_file = { file_name = 'my_output_file.txt' }
--output_to_pipe = { pipe_name = '/tmp/llpipe_17115325107265013479' }                                            
--output_to_pipe = { pipe_env = 'pipename' }
output_to_stdout = {}

--log_bill = { output = 'output_to_pipe' }
--log_txt = { output = 'output_to_stdout' }
log_lorth = { output = 'output_to_stdout' }

alert_lioli = { logger = 'log_txt' }

trout_netflow = { logger = 'log_txt',
                   option_grouped_output = false }                   

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
