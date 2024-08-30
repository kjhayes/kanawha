
#include <kanawha/syscall.h>
#include <kanawha/process.h>
#include <kanawha/file.h>
#include <kanawha/kmalloc.h>
#include <kanawha/assert.h>

#define SYSCALL_WRITE_MAX_CHUNK_SIZE 0x1000

int
syscall_write(
        struct process *process,
        fd_t file,
        size_t dst_offset,
        void __user *src,
        size_t size)
{
    int res;

    dprintk("syscall_write(pid=%ld, file=%ld, dst_offset=0x%llx, src=%p, size=0x%llx)\n",
            (sl_t)process->id,
            (sl_t)file,
            (ull_t)dst_offset,
            src,
            (ull_t)size);

    struct file_descriptor *desc
        = file_table_get_descriptor(
                &process->file_table,
                file);

    if(desc == NULL) {
        eprintk("syscall_write: descriptor does not exist!\n");
        return -ENXIO;
    }

    if((desc->access_flags & FILE_PERM_WRITE) == 0) {
        eprintk("syscall_write: file descriptor does not have write permissions!\n");
        return -EPERM;
    }

    size_t buffer_len = size > SYSCALL_WRITE_MAX_CHUNK_SIZE
        ? SYSCALL_WRITE_MAX_CHUNK_SIZE : size;
    void *buffer = kmalloc(buffer_len);

    while(size > 0)
    {
        size_t amount = buffer_len > size ? size : buffer_len;
        size_t amount_read = amount;

        dprintk("Reading from usermem %p, size=0x%llx\n",
                src, (ull_t)amount_read);
        res = process_read_usermem(
                process,
                buffer,
                src,
                amount_read);
        if(res) {
            goto exit;
        }

        res = fs_node_write(
                desc->node,
                buffer,
                &amount_read,
                dst_offset);
        if(res) {
            eprintk("syscall_write: fs_node_write returned %s\n",
                    errnostr(res));
            goto exit;
        }

        dprintk("Wrote to fs_node, size=0x%llx\n",
                (ull_t)amount_read);
        DEBUG_ASSERT(amount_read <= amount);

        size -= amount_read;
        dst_offset += amount_read;
        src += amount_read;
    }
    res = 0;

exit:
    kfree(buffer);
    return res;
}
