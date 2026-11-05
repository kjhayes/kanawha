
#include <kanawha/proc/file_table.h>
#include <kanawha/syscall.h>

int
syscall_resize(fd_t file, size_t size, unsigned long flags)
{
    int res;

    struct process *process = current_process();

    struct file *desc = file_table_get_file(process->file_table, process, file);
    if(desc == NULL)
    {
        return -ENXIO;
    }

    unsigned long aflags = fs_file_get_access_flags(desc);
    if((aflags & FILE_PERM_WRITE) == 0)
    {
        file_table_put_file(process->file_table, process, desc);
        return -EPERM;
    }
 
    struct fs_node *fs_node = fs_file_get_node(desc);
    if(fs_node == NULL)
    {
        return -EINVAL;
    }
    file_table_put_file(process->file_table, process, desc);

    res = fs_node_setattr(fs_node, FS_NODE_ATTR_DATA_SIZE, size);
    if(res)
    {
        fs_node_put(fs_node);
        return res;
    }

    fs_node_put(fs_node);

    return 0;
}
