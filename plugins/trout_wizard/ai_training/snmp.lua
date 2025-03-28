
serializer_csv = { }
serializer_python = { log_tag = "snmp",
                      data_name = "data",
                      add_print = false }

logger_file = { file_name = 'output/snmp.csv',
                serializer = 'serializer_csv' }

logger_stdout = { serializer = 'serializer_csv' }                

trout_wizard = { tag = 'snmp',
                 logger = 'logger_file',
                 pack_data = false,
                 split_size = 253,
                 concatenate = true                 
               }                   


require "wizard_setup"
