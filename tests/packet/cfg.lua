stream = { }
stream_ip = { }
stream_tcp = { }

test_packet = {
  { cap = "dns8888.pcap", other=12 },
  { cap = "dns1111.pcap" },
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
