
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define SEC_PER_DAY 86400ULL
#define DAYS_PER_YEAR 365
#define DAYS_PER_LEAP_YEAR 366

#define __DIVISIBLE(__val, __by) ((__val % __by) == 0)
#define YEAR_IS_LEAP(__year)                                                   \
    (__DIVISIBLE(__year, 4) &&                                                 \
     !(__DIVISIBLE(__year, 100) && !__DIVISIBLE(__year, 400)))

struct tm *
localtime_r(const time_t *t, struct tm *tm)
{
    tm->tm_isdst = -1; // No info on daylight savings

    // Determine the year (and how many seconds we are into the year
    size_t sec_into_year = *t;
    size_t cur_year = 1900;
    while(1)
    {
        size_t days_in_year =
            YEAR_IS_LEAP(cur_year) ? DAYS_PER_LEAP_YEAR : DAYS_PER_YEAR;
        size_t sec_in_year = days_in_year * SEC_PER_DAY;
        if(sec_into_year >= sec_in_year)
        {
            cur_year++;
            sec_into_year -= sec_in_year;
        }
        else
        {
            break;
        }
    }
    tm->tm_year = cur_year;

    int is_leap = YEAR_IS_LEAP(cur_year);

    // How many days into the year are we?
    size_t days_into_year = sec_into_year / SEC_PER_DAY;
    tm->tm_yday = days_into_year;
    if(tm->tm_yday > 365)
    {
        // Something is wrong...
    }

#define JAN 0
#define FEB 1
#define MAR 2
#define APR 3
#define MAY 4
#define JUN 5
#define JUL 6
#define AUG 7
#define SEP 8
#define OCT 9
#define NOV 10
#define DEC 11

    int day_in_month = tm->tm_yday;
    int month = 0;
    while(1)
    {
        size_t days_in_month;
        switch(month)
        {
        case JAN:
        case MAR:
        case MAY:
        case JUL:
        case AUG:
        case OCT:
        case DEC:
            days_in_month = 31;
            break;
        case APR:
        case JUN:
        case SEP:
        case NOV:
            days_in_month = 30;
            break;
        case FEB:
            days_in_month = is_leap ? 29 : 28;
            break;
        }

        if(day_in_month >= days_in_month)
        {
            month++;
            day_in_month -= days_in_month;
        }
        else
        {
            break;
        }
    }
    tm->tm_mday = day_in_month + 1;
    tm->tm_mon = month;

    size_t sec_into_day = sec_into_year - (SEC_PER_DAY * days_into_year);
    size_t hours_into_day = sec_into_day / (60 * 60);
    size_t sec_into_hour = sec_into_day - (hours_into_day * (60 * 60));
    size_t min_into_hour = sec_into_hour / 60;
    size_t sec_into_min = sec_into_hour - (min_into_hour * 60);

    tm->tm_hour = hours_into_day;
    tm->tm_min = min_into_hour;
    tm->tm_sec = sec_into_min;

    // determine the day of the week
    // Jan 1st 1900 was a monday (hence the added 1)
    size_t total_days = *t / SEC_PER_DAY;
    tm->tm_wday = (1 + total_days) % 7;
}

struct tm *
localtime(const time_t *t)
{
    static struct tm __tm;
    return localtime_r(t, &__tm);
}
