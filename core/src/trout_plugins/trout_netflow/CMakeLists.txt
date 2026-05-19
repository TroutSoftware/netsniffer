set( FILE_LIST
    trout_netflow.cc
    trout_netflow.h
    trout_netflow.private.h
    trout_netflow_data.cc
    trout_netflow_data.h
)

add_library( trout_netflow OBJECT ${FILE_LIST})
