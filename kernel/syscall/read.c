
#include <kanawha/syscall.h>
#include <kanawha/process.h>
#include <kanawha/file.h>
#include <kanawha/kmalloc.h>
#include <kanawha/assert.h>

#define SYSCALL_READ_MAX_CHUNK_SIZE 0x1000

int
syscall_read(
        struct process *process,
        fd_t file,
        void __user *dst,
        size_t src_offset,
        size_t size)
{
    int res;
    struct file_descriptor *desc
        = file_table_get_descriptor(
                &process->file_table,
                file);

    if(desc == NULL) {
        return -ENXIO;
    }

    if((desc->access_flags & FILE_PERM_READ) == 0) {
        return -EPERM;
    }

    size_t buffer_len = size > SYSCALL_READ_MAX_CHUNK_SIZE
        ? SYSCALL_READ_MAX_CHUNK_SIZE : size;
    void *buffer = kmalloc(buffer_len);

    while(size > 0)
    {
        size_t amount = buffer_len > size ? size : buffer_len;
        size_t amount_read = amount;
        res = fs_node_read(
                desc->node,
                buffer,
                &amount_read,
                src_offset);
        if(res) {
            goto err;
        }

        DEBUG_ASSERT(amount_read <= amount);

        res = process_write_usermem(
                process,
                dst,
                buffer,
                amount_read);
        if(res) {
            goto err;
        }

        size -= amount_read;
        src_offset += amount_read;
        dst += amount_read;
    }

err:
    kfree(buffer);
    return res;
}

