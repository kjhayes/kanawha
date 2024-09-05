
#include <kanawha/syscall.h>
#include <kanawha/process.h>
#include <kanawha/file.h>
#include <kanawha/fs.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/assert.h>

#define SYSCALL_CHILDNAME_MAX_NAMELEN 256

int
syscall_childname(
        struct process *process,
        fd_t parent_fd,
        size_t child_index,
        char __user *name_buf,
        size_t buf_len)
{
    int res;

    size_t original_len = buf_len;

    struct file_descriptor *desc =
        file_table_get_descriptor(&process->file_table, parent_fd);
    if(desc == NULL) {
        res = -EINVAL;
        goto err0;
    }

    if((desc->mode_flags & FILE_PERM_READ) == 0) {
        res = -EPERM;
        goto err1;
    }

    size_t num_children;
    res = fs_node_attr(
            desc->node,
            FS_NODE_ATTR_CHILD_COUNT,
            &num_children);
    if(res) {
        goto err1;
    }

    if(child_index >= num_children) {
        res = -ENXIO;
        goto err1;
    }

    if(buf_len > SYSCALL_CHILDNAME_MAX_NAMELEN) {
        buf_len = SYSCALL_CHILDNAME_MAX_NAMELEN;
    }

    char *kernel_buffer = kmalloc(buf_len);
    if(kernel_buffer == NULL) {
        res = -ENOMEM;
        goto err1;
    }

    res = fs_node_child_name(desc->node, child_index, kernel_buffer, buf_len-1);
    kernel_buffer[buf_len] = '\0';

    size_t actual_len = strlen(kernel_buffer);

    DEBUG_ASSERT(actual_len+1 < original_len);

    res = process_write_usermem(
            process,
            name_buf,
            kernel_buffer,
            actual_len+1);
    if(res) {
        goto err2;
    }

    kfree(kernel_buffer);
    file_table_put_descriptor(&process->file_table, desc);
    return 0;

err2:
    kfree(kernel_buffer);
err1:
    file_table_put_descriptor(&process->file_table, desc);
err0:
    return res;
}

