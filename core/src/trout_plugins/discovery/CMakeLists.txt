set( FILE_LIST
    c_string_type.h
    generic_template_header.h
    inspector.cc
    inspector.h
    known_hash.h
    module.cc
    module.h
    parameter_concepts.h
    parameter_param.h
    parameter_param_default_value.h
    parameter_param_help_text.h
    parameter_param_list.h
    parameter_param_name.h
    parameter_param_range.h
    parameter_param_types.h
    pegs.cc
    pegs.h
    plugin_def.cc
    plugin_def.h
    settings.h
)

add_library( discovery OBJECT ${FILE_LIST})
