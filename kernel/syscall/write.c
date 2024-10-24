
#include <kanawha/syscall.h>
#include <kanawha/process.h>
#include <kanawha/fs/file.h>
#include <kanawha/file.h>
#include <kanawha/kmalloc.h>
#include <kanawha/assert.h>
#include <kanawha/fs/node.h>

#define SYSCALL_WRITE_MAX_CHUNK_SIZE 0x1000

ssize_t
syscall_write(
        struct process *process,
        fd_t file,
        void __user *src,
        size_t size)
{
    ssize_t res;

#ifdef CONFIG_DEBUG_SYSCALL_WRITE
    printk("PID(%ld) syscall_write(file=%ld, size=0x%llx)\n",
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
        eprintk("PID(%ld) syscall_write: descriptor (%ld) does not exist!\n",
                process->id, file);
        return -ENXIO;
    }

    if((desc->access_flags & FILE_PERM_WRITE) == 0) {
        eprintk("PID(%ld) syscall_write: file descriptor (%ld) does not have write permissions!\n",
                process->id, desc->table_node.key);
        file_table_put_file(process->file_table, process, desc);
        return -EPERM;
    }

    size_t buffer_len = size > SYSCALL_WRITE_MAX_CHUNK_SIZE
        ? SYSCALL_WRITE_MAX_CHUNK_SIZE : size;
    void *buffer = kmalloc(buffer_len);

    ssize_t amount_to_write = buffer_len > size ? size : buffer_len;
    ssize_t amount_written = amount_to_write;

    dprintk("Reading from usermem %p, size=0x%llx\n",
            src, (ull_t)amount_read);
    res = process_read_usermem(
            process,
            buffer,
            src,
            amount_written);
    if(res) {
        DEBUG_ASSERT(res < 0);
        goto exit;
    }

    amount_written = direct_file_write(
            desc,
            buffer,
            amount_to_write);
    if(amount_written < 0) {
        eprintk("syscall_write: fs_node_write returned %s\n",
                errnostr(res));
        DEBUG_ASSERT(res < 0);
        res = amount_written;
        goto exit;
    }

    desc->seek_offset += amount_written;
    res = amount_written;

exit:
    file_table_put_file(process->file_table, process, desc);
    kfree(buffer);
#ifdef CONFIG_DEBUG_SYSCALL_WRITE
    printk("PID(%lld) syscall_write: returning 0x%llx\n",
            (sll_t)process->id, (ull_t)res);
#endif
    return res;
}
