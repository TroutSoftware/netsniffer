#set (SSH_INCLUDES
#    ssh_types.h
#)

set( FILE_LIST
    alert_lioli.cc
    alert_lioli.h
    common.h
    ips_lioli_bind.cc
    ips_lioli_bind.h
    ips_lioli_tag.cc
    ips_lioli_tag.h
#    ${SSH_INCLUDES}
)


add_library( alert_lioli OBJECT ${FILE_LIST})

#install(FILES ${SSH_INCLUDES}
#    DESTINATION "${INCLUDE_INSTALL_PATH}/service_inspectors/ssh/"
#)
