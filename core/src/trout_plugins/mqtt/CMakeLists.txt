set( FILE_LIST
    client_id_monitor.cc
    client_id_monitor.h
    flow_data.cc
    flow_data.h
    inspector.cc
    inspector.h
    ips_option_mqtt_field.cc
    ips_option_mqtt_field.h
    module.cc
    module.h
    mqtt_protocol_defs.h
    pegs.cc
    pegs.h
    plugin_def.cc
    plugin_def.h
    rules.cc
    rules.h
    settings.cc
    settings.h
    stream_splitter.cc
    stream_splitter.h
)

add_library( mqtt_plugin OBJECT ${FILE_LIST})
