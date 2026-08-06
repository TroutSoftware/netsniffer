set( FILE_LIST
    c_string_type.h
    concepts.h
    dummy.cc
    help_text.h
    name.h

)

add_library( trout_includes OBJECT ${FILE_LIST})
