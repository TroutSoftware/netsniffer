

stream = {}
stream_tcp = {}
stream_udp = {}

serializer_raw = { secret_sequence = "0022445566AABBCCDD"}
logger_tcp = { alias = {serializer = 'serializer_raw'} }
logger_tcp = { serializer = 'serializer_raw' }

trout_netflow2 = { logger = 'logger_tcp' }
