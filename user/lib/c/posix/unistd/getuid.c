
#include <errno.h>
#include <kanawha/process.h>
#include <kanawha/sys-wrappers.h>

uid_t
getuid(void)
{
    int res;
    id_t id;

    res = kanawha_sys_rid(0, RID_SELF | RID_UID, &id);
    if(res)
    {
        errno = res;
        return -1;
    }

    return id;
}
