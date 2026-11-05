
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

    LOG("fd=%ld, fields=0x%lx, mode=0x%lx\n", (sl_t)fd, (ul_t)fields, (ul_t)mode);

    int res;
    struct file *file = file_table_get_file(process->file_table, process, fd);
    if(file == NULL)
    {
        LOG("failed to get file descriptor!\n");
        return -ENXIO;
    }

#define SUPPORTED_MODE_FLAGS (\
      FILE_MODE_NON_BLOCK \
    | FILE_MODE_CLOSE_ON_EXEC \
    )

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
        unsigned long old = fs_file_get_mode_flags(file);
        mode_flags = ((old & (~SUPPORTED_MODE_FLAGS)) | mode_flags);
        res = fs_file_overwrite_mode_flags(file, mode_flags);
    }
    else if(mode == FACCESS_MODE_SET)
    {
        res = fs_file_set_mode_flags(file, mode_flags);
    }
    else if(mode == FACCESS_MODE_CLEAR)
    {
        res = fs_file_clear_mode_flags(file, mode_flags);
    }
    else
    {
        LOG("invalid mode (%lu)!\n", mode);
        res = -EINVAL;
    }

    file_table_put_file(process->file_table, process, file);

    return res;
}
