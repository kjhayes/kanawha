
#include <kanawha/sys-wrappers.h>
#include <kanawha/process.h>
#include <errno.h>

uid_t
geteuid(void)
{
    int res;
    id_t id;

    res = kanawha_sys_rid(
            0,
            RID_SELF|RID_UID,
            &id);
    if(res) {
        errno = res;
        return -1;
    }

    return id;
}
