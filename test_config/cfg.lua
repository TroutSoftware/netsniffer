stream = { }
stream_ip = { }
stream_tcp = { }
ssl = { }
http_inspect = {}

dhcp_monitor = {}

output_to_stdout = {}
log_lorth = { output = 'output_to_stdout' }
alert_lioli = { logger = 'log_lorth' }
trout_netflow = { logger = 'log_lorth' }

wizard = {
    hexes = {
         { service = 'http2', proto = 'tcp',
          to_client = { '???|04 00 00 00 00 00|' },
          to_server = { '|50 52 49 20 2a 20 48 54 54 50 2f 32 2e 30 0d 0a 0d 0a 53 4d 0d 0a 0d 0a|' } },


        { service = 'ssl', proto = 'tcp',
          to_server = { '|16 03|' }, to_client = { '|16 03|' } },
    }
}

binder = {
    { use = { type = 'wizard' } }
}

binder = {
    { when = { service = 'http' }, use = { type = 'http_inspect' } },
    { use = { type = 'wizard' } }
}


trace.modules = {
    wizard = {
        all = 2,
    },
}

ips = {
  include = 'test-local.rules'
}


