
#include <kanawha/syscall.h>
#include <kanawha/process.h>
#include <kanawha/file.h>
#include <kanawha/kmalloc.h>
#include <kanawha/assert.h>

#define SYSCALL_READ_MAX_CHUNK_SIZE 0x1000

ssize_t
syscall_read(
        struct process *process,
        fd_t file,
        void __user *dst,
        size_t size)
{
    ssize_t res;
    struct file_descriptor *desc
        = file_table_get_descriptor(
                process->file_table,
                process,
                file);

    if(desc == NULL) {
        return -ENXIO;
    }

    if((desc->access_flags & FILE_PERM_READ) == 0) {
        file_table_put_descriptor(process->file_table, process, desc);
        return -EPERM;
    }

    size_t buffer_len = size > SYSCALL_READ_MAX_CHUNK_SIZE
        ? SYSCALL_READ_MAX_CHUNK_SIZE : size;
    void *buffer = kmalloc(buffer_len);

    uintptr_t src_offset = desc->seek_offset;

    ssize_t total_read;

    while(size > 0)
    {
        size_t amount_to_read = buffer_len > size ? size : buffer_len;
        size_t amount_read = amount_to_read;

        res = fs_node_read(
                desc->node,
                buffer,
                &amount_read,
                src_offset);
        if(res) {
            DEBUG_ASSERT(res < 0);
            goto exit;
        }

        DEBUG_ASSERT(amount_read <= amount_to_read);

        res = process_write_usermem(
                process,
                dst,
                buffer,
                amount_read);
        if(res) {
            DEBUG_ASSERT(res < 0);
            goto exit;
        }

        if(amount_read == 0) {
            break;
        }

        size -= amount_read;
        src_offset += amount_read;
        dst += amount_read;
        total_read += amount_read;
    }

    desc->seek_offset = src_offset;
    res = total_read;

exit:
    file_table_put_descriptor(process->file_table, process, desc);
    kfree(buffer);
    return res;
}

