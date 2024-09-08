
#include <kanawha/syscall.h>
#include <kanawha/uapi/attr.h>
#include <kanawha/errno.h>
#include <kanawha/file.h>
#include <kanawha/fs.h>
#include <kanawha/process.h>

int
syscall_attr(
        struct process *process,
        fd_t file,
        int attr,
        size_t __user *value)
{
    int res;
    size_t to_write;

    struct file_descriptor *desc =
        file_table_get_descriptor(process->file_table, process, file);

    switch(attr) {
        case FILE_ATTR_TELL:
            to_write = desc->seek_offset;
            break;
        case FILE_ATTR_SIZE:
            res = fs_node_attr(
                    desc->node,
                    FS_NODE_ATTR_END_OFFSET,
                    &to_write);
            if(res) {
                goto exit;
            }
            break;
        case FILE_ATTR_CHILDREN:
            res = fs_node_attr(
                    desc->node,
                    FS_NODE_ATTR_CHILD_COUNT,
                    &to_write);
            if(res) {
                goto exit;
            }
            break;
        default:
            res = -EINVAL;
            goto exit;
    }

    res = process_write_usermem(
            process,
            value,
            &to_write,
            sizeof(size_t));

    if(res) {
        goto exit;
    }

    res = 0;

exit:
    file_table_put_descriptor(process->file_table, process, desc);
    return res;
}

