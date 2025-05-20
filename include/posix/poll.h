#ifndef __ELK_LIBC_POSIX__POLL_H__
#define __ELK_LIBC_POSIX__POLL_H__

struct pollfd
{
    int         fd;        // the following descriptor being polled
    short int   events;    // the input event flags (see below)
    short int   revents;   // the output event flags (see below)
};

typedef unsigned long nfds_t;


#define POLLIN (POLLRDNORM | POLLRDBAND)
#define POLLRDNORM (1ULL<<0)
#define POLLRDBAND (1ULL<<1)
#define POLLPRI    (1ULL<<2)
#define POLLWRNORM (1ULL<<3)
#define POLLOUT (POLLWRNORM)
#define POLLWRBAND (1ULL<<4)
#define POLLERR    (1ULL<<5)
#define POLLHUP    (1ULL<<6)
#define POLLNVAL   (1ULL<<7)

int   poll(struct pollfd[], nfds_t, int);

#endif
