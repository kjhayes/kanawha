
#include <kanawha/process.h>
#include <kanawha/uapi/syscall.h>
#include <kanawha/file.h>
#include <kanawha/fs/node.h>

#define SYSCALL_MKFILE_MAX_NAMELEN 128

int
syscall_mkfile(
        struct process *process,
        fd_t dir_fd,
        char __user * name,
        unsigned long user_flags)
{
    int res;

    struct file *dir_file
        = file_table_get_file(
            process->file_table,
            process,
            dir_fd);
    if(dir_file == NULL) {
        return -ENXIO;
    }
 
    size_t namelen = process_strlen_usermem(
            process,
            name,
            SYSCALL_MKFILE_MAX_NAMELEN+1,
            &namelen);

    if(namelen > SYSCALL_MKFILE_MAX_NAMELEN) {
        // Path is too long
        file_table_put_file(
                process->file_table,
                process,
                dir_file);
        eprintk("PID(%ld) syscall_mkfile: name is too long! len=%llu, (>%llu)\n",
                (sl_t)process->id,
                (ull_t)namelen,
                (ull_t)SYSCALL_MKFILE_MAX_NAMELEN);
        return -EINVAL;
    }

    char namebuf[namelen + 1];
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
        eprintk("syscall_mkfile: failed to read file name! process_read_usermem(%p) -> %s\n",
                name, errnostr(res));
        return res;
    }

    namebuf[namelen] = '\0';

    unsigned long flags = 0;

    res = fs_node_mkfile(
            dir_file->path->fs_node,
            namebuf,
            flags);
    if(res) {
        file_table_put_file(
            process->file_table,
            process,
            dir_file);
        return res;
    }

    file_table_put_file(
            process->file_table,
            process,
            dir_file);
    return 0;
}
