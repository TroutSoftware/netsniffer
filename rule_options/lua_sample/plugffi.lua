ffi = require("ffi")
ffi.cdef[[



struct SnortBuffer
{
    const char* type;
    const uint8_t* data;
    unsigned len;
};

const struct SnortBuffer* get_buffer();

struct SnortEvent
{
    unsigned gid;
    unsigned sid;
    unsigned rev;

    uint32_t event_id;
    uint32_t event_ref;

    const char* msg;
    const char* svc;
};

const struct SnortEvent* get_event();

struct SnortPacket
{
    const char* type;
    uint64_t num;
    unsigned sp;
    unsigned dp;
};

const struct SnortPacket* get_packet();
]]
