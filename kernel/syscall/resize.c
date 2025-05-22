
#include <kanawha/syscall.h>
#include <kanawha/proc/file_table.h>

int
syscall_resize(
        struct process *process,
        fd_t file,
        size_t size,
        unsigned long flags)
{
    int res;

    struct file *desc
        = file_table_get_file(
                process->file_table,
                process,
                file);

    if(desc == NULL) {
        return -ENXIO;
    }
    if(desc->path == NULL) {
        return -EINVAL;
    }
    if(desc->path->fs_node == NULL) {
        return -EINVAL;
    }

    if((desc->access_flags & FILE_PERM_WRITE) == 0) {
        file_table_put_file(process->file_table, process, desc);
        return -EPERM;
    }

    res = fs_node_setattr(
            desc->path->fs_node,
            FS_NODE_ATTR_DATA_SIZE,
            size);
    if(res) {
        file_table_put_file(process->file_table, process, desc);
        return res;
    }

    return 0;
}

