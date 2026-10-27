set( FILE_LIST
    bacnet_ip_defs.h
    inspector.cc
    inspector.h
    module.cc
    module.h    
    pegs.h
    plugin_def.cc
    plugin_def.h
    settings.h
)

add_library( bacnet_ip OBJECT ${FILE_LIST})
