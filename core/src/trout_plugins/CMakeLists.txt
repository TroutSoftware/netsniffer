

add_compile_options(
   -Wall
   -Wextra
   -Werror
   -Wpedantic
   -pedantic-errors
)


add_subdirectory(alert_lioli)
add_subdirectory(arp_monitor)
add_subdirectory(capture_pcap)
add_subdirectory(common)
add_subdirectory(dhcp_monitor)
add_subdirectory(dhcp_option)
add_subdirectory(discovery)
add_subdirectory(icmp_logger)
add_subdirectory(includes)
add_subdirectory(log)
add_subdirectory(mqtt)
add_subdirectory(smnp)
add_subdirectory(trout_netflow)
add_subdirectory(trout_netflow2)

set(STATIC_TROUT_PLUGINS
    $<TARGET_OBJECTS:alert_lioli>
    $<TARGET_OBJECTS:arp_monitor>
    $<TARGET_OBJECTS:capture_pcap>
    $<TARGET_OBJECTS:common>
    $<TARGET_OBJECTS:dhcp_monitor>
    $<TARGET_OBJECTS:dhcp_option>
    $<TARGET_OBJECTS:discovery>
    $<TARGET_OBJECTS:icmp_logger>
    $<TARGET_OBJECTS:mqtt_plugin>
    $<TARGET_OBJECTS:smnp>
    $<TARGET_OBJECTS:trout_log>
    $<TARGET_OBJECTS:trout_includes>
    $<TARGET_OBJECTS:trout_netflow>
    $<TARGET_OBJECTS:trout_netflow2>

    CACHE INTERNAL "STATIC_TROUT_PLUGINS"
)

add_library( trout_plugins OBJECT
    trout_plugins.cc
    trout_plugins.h
)

