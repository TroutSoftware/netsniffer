set( FILE_LIST
    dictionary.h
    dummy.cc
    flow_data.h
    lioli.h
    lioli_path.h
    lioli_tree_generator.h
    log_framework.h
    testable_time.h
    trout_gid.h
    trout_utils.h
)

add_library( trout_includes OBJECT ${FILE_LIST})
