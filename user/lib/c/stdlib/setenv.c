
#include <errno.h>
#include <kanawha/environ.h>
#include <kanawha/sys-wrappers.h>
#include <stdlib.h>

int
setenv(const char *envname, const char *envval, int overwrite)
{
    int res;

    if(!overwrite)
    {
        // Check to make sure it doesn't exist
        int exists;
        exists = kanawha_sys_environ(envname, NULL, 0, ENV_EXIST);
        if(exists < 0)
        {
            errno = exists;
            return -1;
        }
        if(exists != 0)
        {
            errno = -EEXIST;
            return -1;
        }
    }
    res = kanawha_sys_environ(envname, (char *)envval, 0, ENV_SET);
    if(res)
    {
        errno = res;
        return -1;
    }
    return 0;
}
