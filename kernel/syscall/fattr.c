
#include <kanawha/syscall.h>
#include <kanawha/fs/file.h>
#include <kanawha/kmalloc.h>
#include <kanawha/uapi/attr.h>

#ifdef CONFIG_DEBUG_SYSCALL_FATTR
#define LOG(...) printk(__VA_ARGS__)
#else
#define LOG(...)
#endif


int
syscall_fattr(
        struct process *process,
        fd_t fd,
        int attr,
        size_t __user *user_value)
{
    int res;
    struct file *file =
        file_table_get_file(
                process->file_table,
                process,
                fd);
    if(file == NULL) {
        return -EINVAL;
    }

    res = 0;
    size_t value;
    switch(attr) {
        case FILE_ATTR_INODE:
            res = fs_path_get_inode_index(
                    file->path,
                    &value);
            break;
        case FILE_ATTR_PAGESIZE:
            res = fs_path_get_inode_attr(
                    file->path,
                    FS_NODE_ATTR_PAGE_ORDER,
                    &value);
            value = 1ULL<<value;
            break;
        case FILE_ATTR_DATASIZE:
            res = fs_path_get_inode_attr(
                    file->path,
                    FS_NODE_ATTR_DATA_SIZE,
                    &value);
            break;
        default:
            res = -EINVAL;
            break;
    }

    if(res) {
        file_table_put_file(
                process->file_table,
                process,
                file);
        return res;
    }

    res = file_table_put_file(
                process->file_table,
                process,
                file);
    if(res) {
        return res;
    }

    res = process_write_usermem(
            process,
            user_value,
            &value,
            sizeof(size_t));
    if(res) {

    }
            
    return 0;

}

