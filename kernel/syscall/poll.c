
#include <kanawha/syscall.h>
#include <kanawha/uapi/poll.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/fs/file.h>

#ifdef CONFIG_DEBUG_POLL
#define LOG(fmt, ...) printk("PID(%ld) syscall_poll: " fmt, process->id, __VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_poll(
        fd_t file_desc,
        unsigned long watching,
        unsigned long __user *triggered_out)
{
    int res;
    struct file *file;

    struct process *process = current_process();

    LOG("watching=0x%lx\n");

    file = file_table_get_file(
            process->file_table,
            process,
            file_desc);
    if(file == NULL) {
        return -ENXIO;
    }

    unsigned long triggered = 0;

    res = direct_file_poll(file, watching, &triggered);
    if(res) {
        file_table_put_file(process->file_table, process, file);
        return res;
    }

    file_table_put_file(process->file_table, process, file);

    res = process_write_usermem(
            process,
            triggered_out,
            &triggered,
            sizeof(*triggered_out));
    if(res) {
        return res;
    }

    return 0;
}

