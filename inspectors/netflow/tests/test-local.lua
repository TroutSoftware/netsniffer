
output_to_file = { file_name = 'my_output_file.txt' }
output_to_stdout = {}

log_txt = { output = 'output_to_file' }
log_lorth = { output = 'output_to_file' }
log_bill = { output = 'output_to_file' }

alert_lioli = { logger = 'log_lorth' }

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
