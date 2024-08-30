
#include <kanawha/syscall.h>
#include <kanawha/process.h>
#include <kanawha/file.h>

#define SYSCALL_OPEN_MAX_NAMELEN 256

fd_t
syscall_open(
        struct process *process,
        fd_t parent_fd,
        const char __user *name,
        size_t namelen,
        unsigned long access_flags,
        unsigned long mode_flags)
{
    int res;

    if(namelen > SYSCALL_OPEN_MAX_NAMELEN) {
        // Path is too long
        eprintk("PID(%ld) syscall_open: name is too long! len=%llu, (>%llu)\n",
                (sl_t)process->id,
                (ull_t)namelen,
                (ull_t)SYSCALL_OPEN_MAX_NAMELEN);
        return NULL_FD;
    }

    char name_buf[namelen + 1];

    dprintk("syscall_open(parent=%ld, name=%p, namelen=0x%llx, access_flags=0x%llx, mode_flags=0x%llx\n",
            (sl_t)parent_fd, name, (ull_t)namelen, (ull_t)access_flags, (ull_t)mode_flags);
    res = process_read_usermem(
            process,
            (void*)name_buf,
            (void __user*)name,
            namelen);
    if(res) {
        eprintk("syscall_open: failed to read file name! process_read_usermem(%p) -> %s\n",
                name, errnostr(res));
        return NULL_FD;
    }

    name_buf[namelen] = '\0';

    dprintk("PID(%ld) syscall_open(%s)\n",
            (sl_t)process->id, name_buf);

    fd_t fd; 
    if(parent_fd == NULL_FD) {
        // "name" refers to the name of an attached mount
        res = file_table_open_mount(
                &process->file_table,
                name_buf,
                access_flags,
                mode_flags,
                &fd);
        if(res) {
            eprintk("PID(%ld) syscall_open: file_table_open_mount(%s) returned %s\n",
                    (sl_t)process->id, name_buf, errnostr(res));
            return NULL_FD;
        }
    } else {
        res = file_table_open_child(
                &process->file_table,
                parent_fd,
                name_buf,
                access_flags,
                mode_flags,
                &fd); 
        if(res) {
            eprintk("PID(%ld) syscall_open: file_table_open_child(%s) returned %s\n",
                    (sl_t)process->id, name_buf, errnostr(res));
            return NULL_FD;
        }
    }
    dprintk("PID(%ld) syscall_open: fd=%ld\n",
            (sl_t)process->id, (sl_t)fd);
    return fd;
}

