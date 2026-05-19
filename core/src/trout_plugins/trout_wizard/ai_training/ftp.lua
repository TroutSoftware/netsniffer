

--serializer_python = { log_tag = "ftp",
--                      data_name = "data",
--                      add_print = false }

--serializer_csv = {}
serializer_csv = {
  item_separator = " ",
  if_item_blank_then_output = "-",
--  items= { { lookup = "$.#Chunks.chunk.first_from",
--             map = { { if_input = "client", then_output = "S" },
--                     { if_input = "server", then_output = "C" },
--                     { default_output = "O" } } },
--           { lookup = "$.protocol",
--             map = { { if_input = "TCP", then_output = "T" },
--                     { if_input = "UDP", then_output = "U" },
--                     { default_output = "O" } } },
--           { lookup = "$.port", },
--           { lookup_regex = "\\$\\.\\#Chunks\\.chunk\\.(client|server)\\.data",
--             format_as_hex = true,
--             pad_output = { padding = "0",
--                            length = 2048 },
--             truncate_input_after = 1024,
--           }
--  }
} 

logger_file = { file_name = 'output/ftp.csv',
--                serializer = 'serializer_python' }
                serializer = 'serializer_csv' }

logger_stdout = { serializer = 'serializer_csv' }                

trout_wizard = { tag = 'ftp',
                 logger = 'logger_file',
                 pack_data = false,
                 split_size = 253,
                 concatenate = true                 
               }                   


require "wizard_setup"
