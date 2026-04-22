
#include <kanawha/fs/file.h>
#include <kanawha/kmalloc.h>
#include <kanawha/syscall.h>
#include <kanawha/uapi/attr.h>

#ifdef CONFIG_DEBUG_SYSCALL_FATTR
#define LOG(...) printk(__VA_ARGS__)
#else
#define LOG(...)
#endif

int
syscall_fattr(fd_t fd, int attr, size_t __user *user_value)
{
    int res;

    struct process *process = current_process();

    struct file *file = file_table_get_file(process->file_table, process, fd);
    if(file == NULL)
    {
        return -EINVAL;
    }

    res = 0;
    size_t value;
    size_t tmp_value;
    switch(attr)
    {
    case FILE_ATTR_INODE:
        res = fs_path_get_inode_index(file->path, &value);
        break;
    case FILE_ATTR_PAGESIZE:
        res =
            fs_path_get_inode_attr(file->path, FS_NODE_ATTR_PAGE_ORDER, &value);
        value = 1ULL << value;
        break;
    case FILE_ATTR_DATASIZE:
        res =
            fs_path_get_inode_attr(file->path, FS_NODE_ATTR_DATA_SIZE, &value);
        break;
    case FILE_ATTR_TYPES:
        res =
            fs_path_get_inode_attr(file->path, FS_NODE_ATTR_TYPES, &tmp_value);
        value = 0;
        if(res == 0)
        {
            if(tmp_value & FS_NODE_TYPE_FIFO)
            {
                value |= FILE_TYPE_FIFO;
            }
            if(tmp_value & FS_NODE_TYPE_REGULAR)
            {
                value |= FILE_TYPE_REGULAR;
            }
            if(tmp_value & FS_NODE_TYPE_DIRECTORY)
            {
                value |= FILE_TYPE_DIRECTORY;
            }
        }
        break;
    case FILE_ATTR_ACCESS:
        value = 0;
        if(file->mode_flags & FILE_MODE_NON_BLOCK)
        {
            value |= FACCESS_NON_BLOCKING;
        }
        break;
    case FILE_ATTR_CONNECTED:
        res = direct_file_status(file, FILE_STATUS_CONNECTED, &tmp_value);
        if(res == 0)
        {
            value = tmp_value;
        }
        break;
    default:
        res = -EINVAL;
        break;
    }

    if(res)
    {
        file_table_put_file(process->file_table, process, file);
        return res;
    }

    res = file_table_put_file(process->file_table, process, file);
    if(res)
    {
        return res;
    }

    res = process_write_usermem(process, user_value, &value, sizeof(size_t));
    if(res)
    {
        return res;
    }

    return 0;
}
