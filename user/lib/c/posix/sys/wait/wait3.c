
#include <stddef.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>

pid_t
wait3(int *stat_loc, int options, struct rusage *resource_usage)
{
    pid_t res;

    res = waitpid((pid_t)-1, stat_loc, options);
    if(res == -1)
    {
        return res;
    }

    if(resource_usage != NULL)
    {
        memset(resource_usage, 0, sizeof(*resource_usage));
    }

    return res;
}
