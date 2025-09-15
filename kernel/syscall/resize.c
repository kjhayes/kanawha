
#include <kanawha/syscall.h>
#include <kanawha/proc/file_table.h>

int
syscall_resize(
        fd_t file,
        size_t size,
        unsigned long flags)
{
    int res;

    struct process *process = current_process();

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

    struct fs_node *fs_node = fs_path_get_fs_node(desc->path);
    if(fs_node == NULL) {
        return -EINVAL;
    }

    if((desc->access_flags & FILE_PERM_WRITE) == 0) {
        file_table_put_file(process->file_table, process, desc);
        return -EPERM;
    }

    res = fs_node_setattr(
            fs_node,
            FS_NODE_ATTR_DATA_SIZE,
            size);
    if(res) {
        file_table_put_file(process->file_table, process, desc);
        return res;
    }

    return 0;
}

