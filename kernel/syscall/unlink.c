
#include <kanawha/proc/process.h>
#include <kanawha/uapi/syscall.h>
#include <kanawha/proc/file_table.h>
#include <kanawha/fs/node.h>

#ifdef CONFIG_DEBUG_SYSCALL_UNLINK
#define LOG(...) printk(__VA_ARGS__)
#else
#define LOG(...)
#endif

#define SYSCALL_UNLINK_MAX_NAMELEN 128

int
syscall_unlink(
        struct process *process,
        fd_t dir_fd,
        char __user * name)
{
    int res;

    LOG("PID(%ld) syscall_unlink: dir_fd=%ld, name=%p\n",
            (sl_t)process->id,
            (sl_t)dir_fd,
            (void __user *)name);

    struct file *dir_file
        = file_table_get_file(
                process->file_table,
                process,
                dir_fd);
    if(dir_file == NULL) {
        return -ENXIO;
    }

    size_t namelen;
    res = process_strlen_usermem(
            process,
            name,
            SYSCALL_UNLINK_MAX_NAMELEN+1,
            &namelen);
    if(res) {
        LOG("PID(%ld) syscall_unlink: could not get namelen! (err=%s)\n",
                (sl_t)process->id,
                errnostr(res));
        file_table_put_file(
                process->file_table,
                process,
                dir_file);
        return res;
    }

    DEBUG_ASSERT(namelen > 0);
    DEBUG_ASSERT(namelen < SYSCALL_UNLINK_MAX_NAMELEN+1);

    char namebuf[namelen +1];
    res = process_read_usermem(
            process,
            (void*)namebuf,
            (void __user *)name,
            namelen);
    if(res) {
        file_table_put_file(
                process->file_table,
                process,
                dir_file);
        LOG("PID(%ld) syscall_unlink: failed to read usermem!\n",
                (sl_t)process->id);
        return res;
    }
    namebuf[namelen] = '\0';

    res = fs_node_unlink(
            dir_file->path->fs_node,
            namebuf);
    if(res) {
        LOG("PID(%ld) syscall_unlink: failed to unlink file! (err=%s)\n",
                (sl_t)process->id,
                errnostr(res));
        return res;
    }

    return 0;
}

