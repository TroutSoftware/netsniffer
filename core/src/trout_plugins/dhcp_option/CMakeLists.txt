set( FILE_LIST
    flow_data.cc
    flow_data.h
    inspector.cc
    inspector.h
    ips_option.cc
    ips_option.h
    ips_option_ip_filter.cc
    ips_option_ip_filter.h
)

add_library( dhcp_option OBJECT ${FILE_LIST})
