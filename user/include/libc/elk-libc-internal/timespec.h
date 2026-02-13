#ifndef __ELK_LIBC_INTERNAL__TIMESPEC_H__
#define __ELK_LIBC_INTERNAL__TIMESPEC_H__

#include <sys/types.h>

struct timespec {
    time_t  tv_sec;  // seconds
    long    tv_nsec; // nanoseconds
};

struct itimerspec {
    struct timespec  it_interval;  //Timer period. 
    struct timespec  it_value;     //Timer expiration. 
};

#endif
