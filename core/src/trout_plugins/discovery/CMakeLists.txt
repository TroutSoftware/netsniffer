set( FILE_LIST
    generic_template_header.h
    inspector.cc
    inspector.h
    known_hash.h
    module.cc
    module.h
    pegs.cc
    pegs.h
    plugin_def.cc
    plugin_def.h
    settings.h
)

add_library( discovery OBJECT ${FILE_LIST})
