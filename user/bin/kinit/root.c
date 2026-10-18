
#include <kanawha/file.h>
#include <kanawha/mount.h>
#include <kanawha/syscall.h>

int
kinit_set_root_fs(
        const char *source,
        const char *fs_type,
        unsigned long mount_flags)
{
    int res;
    fd_t cur_dir;
    res = kanawha_sys_open("", FILE_PERM_READ, 0, &cur_dir);
    if(res)
    {
        return res;
    }
    res = kanawha_sys_mount(source, cur_dir, "root", fs_type, mount_flags);
    if(res)
    {
        return res;
    }
    kanawha_sys_close(cur_dir);
    res = kanawha_sys_open("root", FILE_PERM_READ, 0, &cur_dir);
    if(res)
    {
        return res;
    }
    res = kanawha_sys_chroot(cur_dir);
    if(res)
    {
        return res;
    }
    res = kanawha_sys_chwdir(cur_dir);
    if(res)
    {
        return res;
    }
    kanawha_sys_close(cur_dir);
    return 0;
}
