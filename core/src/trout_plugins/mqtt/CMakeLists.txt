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
    stream_splitter.cc
    stream_splitter.h
)

add_library( mqtt_plugin OBJECT ${FILE_LIST})
