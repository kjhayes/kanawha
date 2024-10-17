
#include <kanawha/process.h>
#include <kanawha/file.h>
#include <kanawha/assert.h>
#include <kanawha/vmem.h>

int
syscall_chroot(
        struct process *process,
        fd_t fd)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(process));
    DEBUG_ASSERT(KERNEL_ADDR(process->file_table));

    printk("PID(%ld) chroot(%ld)\n",
            process->id, fd);

    struct file *file = file_table_get_file(
            process->file_table,
            process,
            fd);
    if(file == NULL) {
        return -ENXIO;
    }

    if(file->path == NULL) {
        eprintk("PID(%ld) chroot(%ld), file has NULL fs_path!\n");
        return -EINVAL;
    }

    res = process_set_root(process, file->path);
    if(res) {
        file_table_put_file(
                process->file_table,
                process,
                file);
        eprintk("PID(%ld) chroot(%ld), process_set_root returned %s\n",
                process->id, fd, errnostr(res));
        return res;
    }

    res = file_table_put_file(
            process->file_table,
            process,
            file);
    if(res) {
        eprintk("PID(%ld) chroot: failed to put file! (err=%s)\n",
                process->id, errnostr(res));
        return res;
    }

    return 0;
}

