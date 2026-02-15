
#include <endian.h>
#include <byteswap.h>

#define __define_beNtoh(N)\
    uint##N##_t be##N##toh(\
            uint##N##_t x) {\
        if(BIG_ENDIAN == BYTE_ORDER) {\
            return x;\
        } else {\
            return bswap_##N(x);\
        }\
    }

__define_beNtoh(16);
__define_beNtoh(32);
__define_beNtoh(64);
#undef __define_bentoh

#define __define_leNtoh(N)\
    uint##N##_t le##N##toh(\
            uint##N##_t x) {\
        if(LITTLE_ENDIAN == BYTE_ORDER) {\
            return x;\
        } else {\
            return bswap_##N(x);\
        }\
    }

__define_leNtoh(16);
__define_leNtoh(32);
__define_leNtoh(64);
#undef __define_lentoh

#define __define_htobeN(N)\
    uint##N##_t htobe##N(\
            uint##N##_t x) {\
        if(LITTLE_ENDIAN == BYTE_ORDER) {\
            return x;\
        } else {\
            return bswap_##N(x);\
        }\
    }

__define_htobeN(16);
__define_htobeN(32);
__define_htobeN(64);
#undef __define_htobeN

#define __define_htoleN(N)\
    uint##N##_t htole##N(\
            uint##N##_t x) {\
        if(LITTLE_ENDIAN == BYTE_ORDER) {\
            return x;\
        } else {\
            return bswap_##N(x);\
        }\
    }

__define_htoleN(16);
__define_htoleN(32);
__define_htoleN(64);
#undef __define_htoleN

