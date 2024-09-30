
#include <kanawha/syscall.h>
#include <kanawha/process.h>
#include <kanawha/file.h>
#include <kanawha/fs/file.h>
#include <kanawha/kmalloc.h>
#include <kanawha/assert.h>
#include <kanawha/fs/node.h>

#define SYSCALL_READ_MAX_CHUNK_SIZE 0x1000

ssize_t
syscall_read(
        struct process *process,
        fd_t file,
        void __user *dst,
        size_t size)
{
    ssize_t res;

#ifdef CONFIG_DEBUG_SYSCALL_READ
    printk("PID(%ld) syscall_read(file=%ld, size=0x%llx)\n",
            (sl_t)process->id,
            (sl_t)file,
            (ull_t)size);
#endif

    struct file *desc
        = file_table_get_file(
                process->file_table,
                process,
                file);

    if(desc == NULL) {
        return -ENXIO;
    }

    if((desc->access_flags & FILE_PERM_READ) == 0) {
        file_table_put_file(process->file_table, process, desc);
        return -EPERM;
    }

    size_t buffer_len = size > SYSCALL_READ_MAX_CHUNK_SIZE
        ? SYSCALL_READ_MAX_CHUNK_SIZE : size;
    void *buffer = kmalloc(buffer_len);

    ssize_t amount_to_read = buffer_len > size ? size : buffer_len;
    ssize_t amount_read = amount_to_read;

    amount_read = direct_file_read(
            desc,
            buffer,
            amount_to_read);
    if(amount_read < 0) {
        res = amount_read;
        goto exit;
    }

    DEBUG_ASSERT(amount_read <= amount_to_read);

    if(amount_read > 0) {
        res = process_write_usermem(
                process,
                dst,
                buffer,
                amount_read);
        if(res) {
            DEBUG_ASSERT(res < 0);
            goto exit;
        }
    }

    res = amount_read;
    desc->seek_offset += amount_read;

exit:
    file_table_put_file(process->file_table, process, desc);
    kfree(buffer);

#ifdef CONFIG_DEBUG_SYSCALL_READ
    printk("PID(%lld) syscall_read: returning 0x%llx\n",
            (sll_t)process->id, (ull_t)res);
#endif

    return res;
}

