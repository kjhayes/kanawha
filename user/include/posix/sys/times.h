#ifndef __ELK_POSIX__TIMES_H__
#define __ELK_POSIX__TIMES_H__

#include <sys/types.h>

struct tms {
    clock_t  tms_utime;  //User CPU time. 
    clock_t  tms_stime;  //System CPU time. 
    clock_t  tms_cutime; //User CPU time of terminated child processes. 
    clock_t  tms_cstime; //System CPU time of terminated child processes. 
};

clock_t times(struct tms *);

#endif
