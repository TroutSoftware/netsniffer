stream = { }
stream_ip = { }
stream_tcp = { }
http_inspect = { }

wizard = {
    spells =
    {
        { service = 'http', proto = 'tcp',
          to_server = http_methods, to_client = { 'HTTP/' } },
    },
}

network_mapping = { }

binder = {
  { when = { service = 'http' },             use = { type = 'http_inspect' } },
  { use = { type = 'wizard' } },
}


trace.modules = {
    detection = {
        fp_search = 1,
        buffer = 1,
    },
    wizard = {
        all = 2,
    },
}