set (TROUT_COMMON_INCLUDES
    dictionary.h
    flow_data.h
    lioli.h
    lioli_path.h
    lioli_tree_generator.h
    testable_time.h
    trout_gid.h
    trout_utils.h
)

set( FILE_LIST
    ${TROUT_COMMON_INCLUDES}
    dictionary.cc
    lioli.cc
    lioli_path.cc
)

add_library( common OBJECT ${FILE_LIST})

install (FILES ${TROUT_COMMON_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/trout_plugins/common"
)
