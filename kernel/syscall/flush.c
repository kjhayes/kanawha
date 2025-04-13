
#include <kanawha/syscall.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/mount.h>

int
syscall_flush(
        struct process *process,
        fd_t file,
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

    if((desc->access_flags & FILE_PERM_WRITE) == 0) {
        file_table_put_file(process->file_table, process, desc);
        return -EPERM;
    }

    res = direct_file_flush(desc, flags);
    if(res) {
        file_table_put_file(process->file_table, process, desc);
        return res;
    }

    // TODO: REMOVE ME
    // This is just here until I add a better method to
    // sync mounts with the disk (this syncs the entire mount
    // every time that any file is flushed: THIS IS BAD)
    if(desc->path && desc->path->fs_node && desc->path->fs_node->mount) {
        res = fs_mount_sync(desc->path->fs_node->mount);
        if(res) {
            file_table_put_file(process->file_table, process, desc);
            return res;
        }
    }

    file_table_put_file(process->file_table, process, desc);

    return 0;
}

