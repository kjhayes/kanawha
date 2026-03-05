
#include <kanawha/errno.h>
#include <kanawha/fs/file.h>
#include <kanawha/proc/process.h>
#include <kanawha/syscall.h>
#include <kanawha/uapi/attr.h>

#ifdef CONFIG_DEBUG_SYSCALL_FACCESS
#define LOG(fmt, ...)                                                          \
    printk("PID(%ld) syscall_faccess: " fmt, process->id, ##__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_faccess(fd_t fd, unsigned long fields, unsigned long mode)
{
    struct process *process = current_process();

    LOG("fields=0x%lx, mode=0x%lx\n", fields, mode);

    int res;
    struct file *file = file_table_get_file(process->file_table, process, fd);
    if(file == NULL)
    {
        LOG("failed to get file descriptor!\n");
        return -EINVAL;
    }

#define SUPPORTED_MODE_FLAGS FILE_MODE_NON_BLOCK

    unsigned long mode_flags = 0;
    if(fields & FACCESS_NON_BLOCKING)
    {
        mode_flags |= FILE_MODE_NON_BLOCK;
    }
    if(fields & FACCESS_CLOSE_ON_EXEC)
    {
        mode_flags |= FILE_MODE_CLOSE_ON_EXEC;
    }

    res = 0;
    if(mode == FACCESS_MODE_EXACT)
    {
        file->mode_flags =
            (file->mode_flags & ~SUPPORTED_MODE_FLAGS) | mode_flags;
    }
    else if(mode == FACCESS_MODE_SET)
    {
        file->mode_flags |= mode_flags;
    }
    else if(mode == FACCESS_MODE_CLEAR)
    {
        file->mode_flags &= ~mode_flags;
    }
    else
    {
        res = -EINVAL;
    }

    file_table_put_file(process->file_table, process, file);

    return res;
}
