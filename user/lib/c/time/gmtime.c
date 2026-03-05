
#include <time.h>

struct tm *
gmtime_r(const time_t *t, struct tm *tm)
{
    // TODO: This is wrong and does not account
    // for the details of UTC.
    return localtime_r(t, tm);
}

struct tm *
gmtime(const time_t *t)
{
    static struct tm __tm;
    return gmtime_r(t, &__tm);
}
