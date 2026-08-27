set( FILE_LIST
    c_string_type.h
    concepts.h
    dummy.cc
    help_text.h
    name.h
    parameter_concepts.h
    parameter_param.h
    parameter_param_default_value.h
    parameter_param_list.h
    parameter_param_range.h
    parameter_param_types.h

)

add_library( trout_includes OBJECT ${FILE_LIST})
