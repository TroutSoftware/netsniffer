set( FILE_LIST
    log_framework.cc
    logger_file.cc
    logger_file.h
    logger_null.cc
    logger_null.h
    logger_pipe.cc
    logger_pipe.h
    logger_stdout.cc
    logger_stdout.h
    logger_tcp.cc
    logger_tcp.h
    serializer_bill.cc
    serializer_bill.h
    serializer_bin.cc
    serializer_bin.h
    serializer_csv.cc
    serializer_csv.h
    serializer_filter.cc
    serializer_filter.h
    serializer_hex.cc
    serializer_hex.h
    serializer_lorth.cc
    serializer_lorth.h
    serializer_python.cc
    serializer_python.h
    serializer_raw.cc
    serializer_raw.h
    serializer_txt.cc
    serializer_txt.h
)

add_library( trout_log OBJECT ${FILE_LIST})
