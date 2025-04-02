
serializer_csv = { item_separator = " ", }

serializer_python = { log_tag = "ssh",
                      data_name = "data",
                      add_print = false }

logger_file = { file_name = 'output/ssh.csv',
                serializer = 'serializer_csv' }

logger_stdout = { serializer = 'serializer_csv' }                

trout_wizard = { tag = 'ssh',
                 logger = 'logger_file',
                 pack_data = false,
                 split_size = 253,
                 concatenate = true                 
               }                   

require "wizard_setup"
