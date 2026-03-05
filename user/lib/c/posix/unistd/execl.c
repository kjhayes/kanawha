
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

int
execl(const char *path, const char *arg0, ... /*, (char *)0 */)
{
    int res;

    va_list args;
    va_start(args, arg0);

    int argc = 1;
    char **argv = malloc(argc * sizeof(char *));
    if(argv == NULL)
    {
        errno = -ENOMEM;
        return -1;
    }

    argv[0] = (char *)arg0;
    while(1)
    {
        char *arg = va_arg(args, char *);

        argc++;
        argv = realloc(argv, argc * sizeof(char *));
        if(argv == NULL)
        {
            res = -ENOMEM;
            break;
        }

        argv[argc - 1] = arg;

        if(arg == (char *)0)
        {
            res = 0;
            break;
        }
    }
    if(res)
    {
        errno = res;
        return -1;
    }
    argc--; // Don't count the final NULL entry

    res = execv(path, argv);

    free(argv);

    va_end(args);
    return res;
}
