
#include <kanawha/assert.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/proc/process.h>
#include <kanawha/vmem.h>

#ifdef CONFIG_DEBUG_SYSCALL_CHROOT
#define LOG(...) printk(__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_chroot(fd_t fd)
{
    int res;

    struct process *process = current_process();

    DEBUG_ASSERT(KERNEL_ADDR(process));
    DEBUG_ASSERT(KERNEL_ADDR(process->file_table));

    LOG("PID(%ld) chroot(%ld)\n", process->id, fd);

    struct file *file = file_table_get_file(process->file_table, process, fd);
    if(file == NULL)
    {
        return -ENXIO;
    }

    struct fs_path *path = fs_file_get_path(file);
    if(path == NULL)
    {
        LOG("PID(%ld) chroot(%ld), file has NULL fs_path!\n");
        fs_file_put(file);
        return -EINVAL;
    }
    fs_file_put(file);

    res = process_set_root_directory(process, path);
    if(res)
    {
        LOG("PID(%ld) chroot(%ld), process_set_root_directory returned "
            "%s\n",
            process->id,
            fd,
            errnostr(res));
        fs_path_put(path);
        return res;
    }

    // also set the working directory to the new root directory
    res = process_set_working_directory(process, path);
    if(res)
    {
        LOG("PID(%ld) chroot(%ld), process_set_working_directory "
            "returned %s\n",
            process->id,
            fd,
            errnostr(res));
        // TODO: We should probably restore the old root directory here
        //       (If we fail at restoring, we should probably kill the
        //       process)
        fs_path_put(path);
        return res;
    }

    fs_path_put(path);
    return 0;
}
