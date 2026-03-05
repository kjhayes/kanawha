#ifndef __ELK_LIBC__TIME_H__
#define __ELK_LIBC__TIME_H__

#include <elk-libc-internal/sigevent.h>
#include <elk-libc-internal/timespec.h>
#include <sys/types.h>

struct tm
{
    int tm_sec;   // seconds [0,61]
    int tm_min;   // minutes [0,59]
    int tm_hour;  // hour [0,23]
    int tm_mday;  // day of month [1,31]
    int tm_mon;   // month of year [0,11]
    int tm_year;  // years since 1900
    int tm_wday;  // day of week [0,6] (Sunday = 0)
    int tm_yday;  // day of year [0,365]
    int tm_isdst; // daylight savings flag
};

#define CLOCKS_PER_SEC (1000000UL)

char *
asctime(const struct tm *);
char *
asctime_r(const struct tm *, char *);
clock_t
clock(void);
int
clock_getres(clockid_t, struct timespec *);
int
clock_gettime(clockid_t, struct timespec *);
int
clock_settime(clockid_t, const struct timespec *);
char *
ctime(const time_t *);
char *
ctime_r(const time_t *, char *);
double
difftime(time_t, time_t);
struct tm *
getdate(const char *);
struct tm *
gmtime(const time_t *);
struct tm *
gmtime_r(const time_t *, struct tm *);
struct tm *
localtime(const time_t *);
struct tm *
localtime_r(const time_t *, struct tm *);
time_t
mktime(struct tm *);
int
nanosleep(const struct timespec *, struct timespec *);
size_t
strftime(char *restrict,
         size_t,
         const char *restrict,
         const struct tm *restrict);
char *
strptime(const char *, const char *, struct tm *);
time_t
time(time_t *);
int timer_delete(timer_t);
int
timer_gettime(timer_t, struct itimerspec *);
int timer_getoverrun(timer_t);
int
timer_settime(timer_t, int, const struct itimerspec *, struct itimerspec *);
void
tzset(void);
int
timer_create(clockid_t, struct sigevent *, timer_t *);

#endif
