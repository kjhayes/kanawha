
#include <time.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>

struct strftime_state {
    const struct tm *timeptr;
    char *restrict s;
    size_t n;
    size_t written;

    int escaped;
    int zero_mod;
    int E_mod;
};

static inline void
strftime_printf(
        struct strftime_state *state,
        const char *fmt,
        ...)
{
    va_list args;
    va_start(args, fmt);

    size_t written = vsnprintf(state->s, state->n, fmt, args);
    if(written > state->n) {
        state->n = 0;
        state->written += written;
        // n and s become out of sync here
        // (this shouldn't happen though if vsnprintf is correct)
    } else {
        state->n -= written;
        state->s += written;
        state->written += written;
    }

    va_end(args);
    return;
}

static inline void
strftime_putc(
        struct strftime_state *state,
        char c)
{
    if(state->n > 0) {
        *state->s = c;
        state->written++;
        state->n--;
    }
}

static inline void
strftime_puts(
        struct strftime_state *state,
        const char *str)
{
    // TODO use actual string.h functions for this
    //      to make it faster for long strings
    while(*str) {
        strftime_putc(state, *str);
        str++;
    }
}

static inline void
strftime_start_escaped(
        struct strftime_state *state)
{
    state->escaped = 1;
    state->zero_mod = 0;
    state->E_mod = 0;
}
static inline void
strftime_end_escaped(
        struct strftime_state *state)
{
    state->escaped = 0;
}

static inline void
strftime_abv_weekday(
        struct strftime_state *state
        )
{
    const char *wdy;
    switch(state->timeptr->tm_wday) {
        case 0: wdy = "SUN"; break;
        case 1: wdy = "MON"; break;
        case 2: wdy = "TUE"; break;
        case 3: wdy = "WED"; break;
        case 4: wdy = "THU"; break;
        case 5: wdy = "FRI"; break;
        case 6: wdy = "SAT"; break;
        default:
                wdy = "???"; break;
    }

    strftime_puts(state, wdy);
}

static inline size_t
strftime_full_weekday(
        struct strftime_state *state)
{
    const char *wdy;
    switch(state->timeptr->tm_wday) {
        case 0: wdy = "Sunday"; break;
        case 1: wdy = "Monday"; break;
        case 2: wdy = "Tuesday"; break;
        case 3: wdy = "Wednesday"; break;
        case 4: wdy = "Thurday"; break;
        case 5: wdy = "Friday"; break;
        case 6: wdy = "Saturday"; break;
        default:
                wdy = "???"; break;
    }

    strftime_puts(state, wdy);   
}

static inline size_t
strftime_abv_month(
        struct strftime_state *state)
{
    const char *mon;
    switch(state->timeptr->tm_wday) {
        case 0:  mon = "JAN"; break;
        case 1:  mon = "FEB"; break;
        case 2:  mon = "MAR"; break;
        case 3:  mon = "APR"; break;
        case 4:  mon = "MAY"; break;
        case 5:  mon = "JUN"; break;
        case 6:  mon = "JUL"; break;
        case 7:  mon = "AUG"; break;
        case 8:  mon = "SEP"; break;
        case 9:  mon = "OCT"; break;
        case 10: mon = "NOV"; break;
        case 11: mon = "DEC"; break;
        default:
                mon = "???"; break;
    }

    strftime_puts(state, mon);
}

static inline size_t
strftime_full_month(
        struct strftime_state *state)
{
    const char *mon;
    switch(state->timeptr->tm_wday) {
        case 0:  mon = "January"; break;
        case 1:  mon = "February"; break;
        case 2:  mon = "March"; break;
        case 3:  mon = "April"; break;
        case 4:  mon = "May"; break;
        case 5:  mon = "June"; break;
        case 6:  mon = "July"; break;
        case 7:  mon = "August"; break;
        case 8:  mon = "September"; break;
        case 9:  mon = "October"; break;
        case 10: mon = "November"; break;
        case 11: mon = "December"; break;
        default:
                mon = "???"; break;
    }

    strftime_puts(state, mon);
}

size_t strftime(
        char *restrict s,
        size_t maxsize,
        const char *restrict format,
        const struct tm *restrict timeptr)
{
    struct strftime_state state;
    state.written = 0;
    state.s = s;
    state.n = maxsize;
    state.timeptr = timeptr;

    state.escaped = 0;
    state.zero_mod = 0;
    state.E_mod = 0;

    while(*format) {
        char c = *format;

        if(!state.escaped) {
            switch(c) {
                case '%':
                    strftime_start_escaped(&state);
                    break;
                default:
                    // Regular character
                    strftime_putc(&state, c);
                    break;
            }
        } else {
            switch(c) {
                case '%':
                    strftime_putc(&state, '%');
                    strftime_end_escaped(&state);
                    break;
                case 'E':
                    if(state.E_mod) {
                        // %EE?
                        strftime_puts(&state, "%EE");
                        strftime_end_escaped(&state);
                    } else {
                        state.E_mod = 1;
                    }
                    break;
                case '0':
                    if(state.zero_mod) {
                        // %00?
                        strftime_puts(&state, "%00");
                        strftime_end_escaped(&state);
                    } else {
                        state.zero_mod = 1;
                    }
                    break;
                case 'a':
                    strftime_abv_weekday(&state);
                    strftime_end_escaped(&state);
                    break;
                case 'A':
                    strftime_full_weekday(&state);
                    strftime_end_escaped(&state);
                    break;
                case 'b':
                    strftime_abv_month(&state);
                    strftime_end_escaped(&state);
                    break;
                case 'B':
                    strftime_full_month(&state);
                    strftime_end_escaped(&state);
                    break;
                case 'd':
                    strftime_printf(&state, "%d", state.timeptr->tm_mday);
                    strftime_end_escaped(&state);
                case 'D':
                    strftime_printf(&state, "%d/%d/%d",
                            state.timeptr->tm_mday // TODO
                            );
                    strftime_end_escaped(&state);
                default:
                    // Either it is an invalid specifier,
                    // or we don't support the specifier,
                    // in either case, just print out the specifier to
                    // make debugging easier.
                    strftime_putc(&state, '%');
                    strftime_putc(&state, c);
                    strftime_end_escaped(&state);
                    break;
            }
        }

        format++;
    }
}

