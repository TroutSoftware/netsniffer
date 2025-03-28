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

serializer_csv = { string = 'THIS IS THE STRING',
                   my_table = {param_1 = "another string",
                               string = "inside string"},
                   my_list = {"item2", "item3"},
                   my_lookup = {{key = "k1",
                                 value = "v1"},
                                {key = "k2",
                                 value = "v2"},
                               }
                   }

stream = {}
stream_icmp = {}
stream_tcp = {}
stream_udp = {}
stream_ip = {}


binder = {
  { use = {type = 'trout_wizard'} }
}
