
#include <time.h>

time_t
mktime(struct tm *tm)
{
    // NOTE: This is INCORRECT (but I don't really care) -KJH

    unsigned long value;

    // Years
    value = tm->tm_year;

    // Days
    value *= 365;
    value += tm->tm_yday;

    // Hours
    value *= 24;
    value += tm->tm_hour;

    // Minutes
    value *= 60;
    value += tm->tm_min;

    // Seconds
    value *= 60;
    value += tm->tm_sec;

    return (time_t)value;
}

