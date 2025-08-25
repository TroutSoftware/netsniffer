

stream = {}
stream_tcp = {}
stream_udp = {}

serializer_raw = { secret_sequence = "0022445566AABBCCDD"}

logger_tcp = { serializer = 'serializer_raw' ,
                    alias = 'main-alias',
                    output_ip = '1234323431',
                    output_port = 1,
              {serializer = "level1_logA",
                    alias = "level1_nameA",
                    output_ip = '127.0.0.1',
                    output_port = 5},
              {serializer = "level1_logB",
                    alias = "level1_nameB",
                    output_ip = '123.132.2.1',
                    output_port = 8080}

}

trout_netflow2 = { logger = 'logger_tcp' }
