
#include <kanawha/sys-wrappers.h>
#include <kanawha/process.h>
#include <errno.h>

gid_t
getegid(void)
{
    int res;
    id_t id;

    res = kanawha_sys_rid(
            0,
            RID_SELF|RID_GID,
            &id);
    if(res) {
        errno = res;
        return -1;
    }

    return id;
}
