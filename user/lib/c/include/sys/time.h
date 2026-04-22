#ifndef __ELK_POSIX__TIME_H__
#define __ELK_POSIX__TIME_H__

#include <sys/types.h>

#define FD_SET_SIZE 64

typedef struct
{
    long fds_bits[(FD_SET_SIZE / sizeof(long)) +
                  (!!(FD_SET_SIZE %
                      sizeof(long)))]; // bit mask for open file descriptions
} fd_set;

#define ITIMER_REAL (0)
#define ITIMER_VIRTUAL (1)
#define ITIMER_PROF (2)

struct timeval
{
    time_t tv_sec;       // seconds
    suseconds_t tv_usec; // microseconds
};

struct timezone
{
    int tz_minuteswest; /* minutes west of Greenwich */
    int tz_dsttime;     /* type of DST correction */
};

struct itimerval
{
    struct timeval it_interval; // timer interval
    struct timeval it_value;    // current value
};

void
FD_CLR(int fd, fd_set *fdset);
int
FD_ISSET(int fd, fd_set *fdset);
void
FD_SET(int fd, fd_set *fdset);
void
FD_ZERO(fd_set *fdset);

int
getitimer(int, struct itimerval *);
int
setitimer(int, const struct itimerval *, struct itimerval *);
int
gettimeofday(struct timeval *tv, struct timezone *tz);
int
settimeofday(const struct timeval *tv, const struct timezone *tz);
int
select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int
utimes(const char *, const struct timeval[2]);

#endif
