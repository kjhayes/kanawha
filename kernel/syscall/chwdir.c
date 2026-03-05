
#include <kanawha/assert.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/proc/process.h>
#include <kanawha/vmem.h>

#ifdef CONFIG_DEBUG_SYSCALL_CHWDIR
#define LOG(...) printk(__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_chwdir(fd_t fd)
{
    int res;

    struct process *process = current_process();

    DEBUG_ASSERT(KERNEL_ADDR(process));
    DEBUG_ASSERT(KERNEL_ADDR(process->file_table));

    LOG("PID(%ld) chwdir(%ld)\n", process->id, fd);

    struct file *file = file_table_get_file(process->file_table, process, fd);
    if(file == NULL)
    {
        return -ENXIO;
    }

    if(file->path == NULL)
    {
        LOG("PID(%ld) chwdir(%ld), file has NULL fs_path!\n");
        return -EINVAL;
    }

    res = process_set_working_directory(process, file->path);
    if(res)
    {
        file_table_put_file(process->file_table, process, file);
        LOG("PID(%ld) chwdir(%ld), process_set_working_directory "
            "returned %s\n",
            process->id,
            fd,
            errnostr(res));
        return res;
    }

    res = file_table_put_file(process->file_table, process, file);
    if(res)
    {
        LOG("PID(%ld) chwdir: failed to put file! (err=%s)\n",
            process->id,
            errnostr(res));
        return res;
    }

    return 0;
}
