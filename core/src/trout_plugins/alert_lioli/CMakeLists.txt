
set( FILE_LIST
    alert_lioli.cc
    alert_lioli.h
    common.h
    ips_lioli_bind.cc
    ips_lioli_bind.h
    ips_lioli_clear.cc
    ips_lioli_clear.h
    ips_lioli_tag.cc
    ips_lioli_tag.h
)


add_library( alert_lioli OBJECT ${FILE_LIST})

