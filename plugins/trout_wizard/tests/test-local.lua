serializer_txt = { }
serializer_lorth = { }
serializer_bill = { bill_secret_sequence = '001122334455667788' }
serializer_python = { log_tag = "format" }


logger_file = { file_name = 'test.py',
                serializer = 'serializer_python' }
logger_null = { }
logger_stdout = { serializer = 'serializer_python' }

trout_wizard = { logger = 'logger_file',
                 pack_data = true,
                 split_size = 253,
                 concatenate = true
               }                   

stream = {}
stream_icmp = {}
stream_tcp = {}
stream_udp = {}
stream_ip = {}


binder = {
  { use = {type = 'trout_wizard'} }
}
