#ifndef __ELK_POSIX__RESOURCE_H__
#define __ELK_POSIX__RESOURCE_H__

#include <stdint.h>
#include <sys/time.h>

#define PRIO_PROCESS (1)
#define PRIO_PGRP (2)
#define PRIO_USER (3)

typedef uint64_t rlim_t;

#define RLIM_INFINITY ((uint64_t)-1)
#define RLIM_SAVED_MAX ((uint64_t)-2)
#define RLIM_SAVED_CUR ((uint64_t)-3)

#define RUSAGE_SELF (1)
#define RUSAGE_CHILDREN (2)

struct rlimit
{
    rlim_t rlim_cur; // the current (soft) limit
    rlim_t rlim_max; // the hard limit
};

struct rusage
{
    struct timeval ru_utime; // user time used
    struct timeval ru_stime; // system time used
};

enum
{
    RLIMIT_CORE,
    RLIMIT_CPU,
    RLIMIT_DATA,
    RLIMIT_FSIZE,
    RLIMIT_NOFILE,
    RLIMIT_STACK,
    RLIMIT_AS,
};

int
getpriority(int, id_t);
int
getrlimit(int, struct rlimit *);
int
getrusage(int, struct rusage *);
int
setpriority(int, id_t, int);
int
setrlimit(int, const struct rlimit *);

#endif
