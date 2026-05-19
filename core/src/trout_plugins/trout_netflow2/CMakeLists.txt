set( FILE_LIST
    cache.cc
    cache.h
    cache_concepts.h
    cache_template_serializer.h
    flow_data.cc
    flow_data.h
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

add_library( trout_netflow2 OBJECT ${FILE_LIST})
