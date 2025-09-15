
#include <kanawha/syscall.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/mount.h>

#ifdef CONFIG_DEBUG_SYSCALL_FLUSH
#define LOG(...) printk(__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_flush(
        fd_t file,
        unsigned long flags) 
{
    int res;

    struct process *process = current_process();

    LOG("PID(%ld) syscall_flush: file=%ld, flags=0x%lx\n",
            (sl_t)process->id,
            (sl_t)file,
            (ul_t)flags);

    struct file *desc
        = file_table_get_file(
                process->file_table,
                process,
                file);
    if(desc == NULL) {
        LOG("syscall_flush: failed to get file!\n");
        return -ENXIO;
    }

    // TODO We should be checking this in some capacity
    // if((desc->access_flags & FILE_PERM_WRITE) == 0) {
    //     file_table_put_file(process->file_table, process, desc);
    //     LOG("syscall_flush: cannot flush a file not opened for writing!\n");
    //     return -EPERM;
    // }

    res = direct_file_flush(desc, flags);
    if(res) {
        LOG("syscall_flush: direct_file_flush failed!\n");
        file_table_put_file(process->file_table, process, desc);
        return res;
    }

    struct fs_node *fs_node = fs_path_get_fs_node(desc->path);
    if(fs_node == NULL) {
        file_table_put_file(process->file_table, process, desc);
        return -EINVAL;
    }

    res = fs_node_flush(fs_node, 0);
    if(res) {
        LOG("syscall_flush: failed to flush fs_node!\n");
        file_table_put_file(process->file_table, process, desc);
        return res;
    }

    // TODO: REMOVE ME
    // This is just here until I add a better method to
    // sync mounts with the disk (this syncs the entire mount
    // every time that any file is flushed: THIS IS BAD)
    if(fs_node && fs_node->mount) {
        res = fs_mount_sync(fs_node->mount);
        if(res) {
            LOG("syscall_flush: failed to sync file mount!\n");
            file_table_put_file(process->file_table, process, desc);
            return res;
        }
    }

    file_table_put_file(process->file_table, process, desc);

    return 0;
}

