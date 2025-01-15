

serializer_txt = {}
serializer_lorth = {}
serializer_bill = { bill_secret_sequence = '001122334455667788' }
--serializer_bill = { bill_secret_env = 'secret_bill'}


logger_file = { file_name = 'test.lorth',
                serializer = 'serializer_lorth' }
logger_null = { }
logger_stdout = { serializer = 'serializer_txt' }
logger_pipe = { serializer = 'serializer_bill',
                pipe_name = "/tmp/my_pipe",
                restart_interval_s = '60' }

alert_lioli = { logger = 'log_file' }

trout_netflow = { logger = 'log_file' }                   

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
