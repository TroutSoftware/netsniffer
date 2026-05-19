set( FILE_LIST
    common.cc
    common.h
    filter.cc
    filter.h
    inspector.cc
    inspector.h
    module.cc
    module.h
    pcap_dumper.cc
    pcap_dumper.h
    plugin_def.h
    settings.cc
    settings.h
)

add_library( capture_pcap OBJECT ${FILE_LIST})
