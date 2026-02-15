
#include <time.h>
#include <stddef.h>

time_t
time(time_t *time_out)
{
    time_t ret;

    // TODO
    ret = (time_t)(-1);

    if(time_out != NULL) {
        *time_out = ret;
    }
    return ret;
}
