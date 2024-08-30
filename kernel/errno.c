
#include <kanawha/errno.h>
#include <kanawha/export.h>

const char *
errnostr(int errno) 
{
    const char *str = "EUNKNOWN";
    if(errno < 0) {
        errno = -errno;
    }
    switch(errno) {
#define DECLARE_ERRNOSTR_CASE(ERRNO,num,...)\
        case num: \
            str=#ERRNO; \
            break;
XFOR_ERRNO(DECLARE_ERRNOSTR_CASE)
    }
    return str;
}

EXPORT_SYMBOL(errnostr);

