
#include "elk-libc-internal/size_t.h"
#include "elk-libc-internal/errno.h"
#include <assert.h>
#include <errno.h>

char *strerror(
        int errnum)
{
    if(errnum < 0) {
	errnum = -errnum;
    }
    switch(errnum) 
    {

#define STRERROR_CASE(__ERRNO,__VALUE,...)\
        case __VALUE: \
            return #__ERRNO ;

ERRNO_XLIST(STRERROR_CASE)

        default:
            return "EUNKNOWN";
    }
#undef STRERROR_CASE
}

