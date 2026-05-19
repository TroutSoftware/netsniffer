set( FILE_LIST
    inspector.cc
    inspector.h
    module.cc
    module.h
    pegs.cc
    pegs.h
    plugin_def.cc
    plugin_def.h
    settings.cc
    settings.h
)

add_library( icmp_logger OBJECT ${FILE_LIST})
