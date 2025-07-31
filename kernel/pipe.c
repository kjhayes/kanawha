
#include <kanawha/pipe.h>
#include <kanawha/init.h>
#include <kanawha/stddef.h>
#include <kanawha/ptree.h>
#include <kanawha/types.h>
#include <kanawha/spinlock.h>
#include <kanawha/lock.h>
#include <kanawha/proc/process.h>
#include <kanawha/uapi/poll.h>
#include <kanawha/usermode.h>
#include <kanawha/kmalloc.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/file.h>

/*
 * At this point, PipeFS is a "pseudo" filesystem,
 * which cannot be properly mounted,
 * and really just allows creation of anonymous pipes,
 *
 * you can try to load any "inode" and the mount
 * will just create a new pipe, so if the fs subsystem
 * ever tried to "load" the same node twice without unloading,
 * then we would leak memory
 */

#define DEFAULT_PIPE_BUFSIZE PAGE_SIZE_4KB

static struct fs_node_ops
pipe_fs_node_ops =
{
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_read_page,
    .load_page = fs_node_cannot_load_page,
    .unload_page = fs_node_cannot_unload_page,
    .flush_page = fs_node_cannot_flush_page,
    .flush = fs_node_flush_nop,
    .getattr = fs_node_cannot_getattr,
    .setattr = fs_node_cannot_setattr,
    .lookup = fs_node_cannot_lookup,
    .mkfile = fs_node_cannot_mkfile,
    .mkdir = fs_node_cannot_mkdir,
    .link = fs_node_cannot_link,
    .symlink = fs_node_cannot_symlink,
    .unlink = fs_node_cannot_unlink,
};

static inline int
pipe_read_empty(struct pipe *pipe)
{
    return pipe->head == pipe->tail;
}

static inline int
pipe_write_full(struct pipe *pipe)
{
    return (((pipe->head+1)%pipe->buflen) == pipe->tail);
}

static ssize_t 
pipe_fs_file_read(
        struct file *file,
        void *buffer,
        ssize_t amount,
        unsigned long flags)
{
    dprintk("pipefs read: amount=%p\n", amount);
    if(amount == 0) {
        return 0;
    }

    struct fs_node *node = fs_path_get_fs_node(file->path);
    if(node == NULL) {
        return -ENXIO;
    }
    struct pipe *pipe = node->backing.priv_state;

    DEBUG_ASSERT(KERNEL_ADDR(pipe));
    DEBUG_ASSERT(KERNEL_ADDR(pipe->buffer));
    DEBUG_ASSERT(KERNEL_ADDR(buffer));
    DEBUG_ASSERT(pipe->buflen > pipe->head);
    DEBUG_ASSERT(pipe->buflen > pipe->tail);

    ssize_t read = 0;
    spin_lock(&pipe->lock);

    while(read <= 0) {
        if(!pipe_read_empty(pipe)) {
            // The buffer is non-empty
            *(uint8_t*)buffer = ((uint8_t*)pipe->buffer)[pipe->tail];
            dprintk("PID(%ld, EXEC(%s)) PIPE(%p) Reading: %c\n",
                    current_process()->id,
                    current_process()->tracked_exec != NULL ? current_process()->tracked_exec : "UNKNOWN",
                    pipe, *(uint8_t*)buffer);
            pipe->tail = (pipe->tail + 1) % pipe->buflen;
            read += 1;
            break;
        } else {
            int can_block = !(flags & FS_FILE_READ_NON_BLOCKING);
            if(can_block) {
                spin_unlock(&pipe->lock);
                dprintk("pipe_fs_read (SLEEPING)\n");
                wait_on(&pipe->read_queue);
                spin_lock(&pipe->lock);
            } else {
                if(read == 0) {
                    read = -EWOULDBLOCK;
                }
                break;
            }
        }
    }

    spin_unlock(&pipe->lock);
    if(read > 0) {
        wake_all(&pipe->write_queue);
    }
    return read;
}

static ssize_t 
pipe_fs_file_write(
        struct file *file,
        void *buffer,
        ssize_t amount,
        unsigned long flags)
{
    if(amount == 0) {
        return 0;
    }

    struct fs_node *node = fs_path_get_fs_node(file->path);
    if(node == NULL) {
        return -ENXIO;
    }
    struct pipe *pipe = node->backing.priv_state;

    DEBUG_ASSERT(KERNEL_ADDR(pipe));
    DEBUG_ASSERT(KERNEL_ADDR(pipe->buffer));
    DEBUG_ASSERT(KERNEL_ADDR(buffer));
    DEBUG_ASSERT(pipe->buflen > pipe->head);
    DEBUG_ASSERT(pipe->buflen > pipe->tail);

    ssize_t written = 0;
    spin_lock(&pipe->lock);

    // TODO: Allow writes of more than a byte at a time
    while(written <= 0) {
        if(!pipe_write_full(pipe)) {
            // The buffer still has room
            dprintk("PID(%ld, EXEC(%s)) PIPE(%p) Writing: %c\n",
                    current_process()->id,
                    current_process()->tracked_exec != NULL ? current_process()->tracked_exec : "UNKNOWN",
                    pipe, *(uint8_t*)buffer);
            ((uint8_t*)pipe->buffer)[pipe->head] = *(uint8_t*)buffer;
            pipe->head = (pipe->head + 1) % pipe->buflen;
            written += 1;
            break;
        } else {
            int can_block = !(flags & FS_FILE_WRITE_NON_BLOCKING);
            if(can_block) {
                spin_unlock(&pipe->lock);
                dprintk("pipe_fs_write (SLEEPING)\n");
                wait_on(&pipe->write_queue);
                spin_lock(&pipe->lock);
            } else {
                if(written == 0) {
                    written = -EWOULDBLOCK;
                }
                break;

            }
        }
    }

    spin_unlock(&pipe->lock);
    if(written > 0) {
        wake_all(&pipe->read_queue);
    }
    return written;
}

static int
pipe_fs_file_poll(
        struct file *file,
        unsigned long watching,
        unsigned long *triggered_out)
{
    dprintk("pipe_fs_file_poll\n");
    struct fs_node *node = fs_path_get_fs_node(file->path);
    if(node == NULL) {
        return -ENXIO;
    }
    struct pipe *pipe = node->backing.priv_state;

    spin_lock(&pipe->lock);

    unsigned long triggered = 0;

    if(watching & POLL_WRITE_NONBLOCKING) {
        if(!pipe_write_full(pipe)) {
            triggered |= POLL_WRITE_NONBLOCKING;
        }
    }
    if(watching & POLL_READ_NONBLOCKING) {
        if(!pipe_read_empty(pipe)) {
            triggered |= POLL_READ_NONBLOCKING;
        }
    }

    spin_unlock(&pipe->lock);

    *triggered_out = triggered;

    return 0;
}

static struct fs_file_ops
pipe_fs_file_ops =
{
    .read = pipe_fs_file_read,
    .write = pipe_fs_file_write,

    .flush = fs_file_nop_flush,
    .seek = fs_file_seek_pinned_zero,
    .poll = pipe_fs_file_poll,

    .dir_begin = fs_file_cannot_dir_begin,
    .dir_next = fs_file_cannot_dir_next,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
};

static int
pipe_fs_root_index(struct fs_mount *mnt, size_t *index)
{
    // Cannot mount pipefs the traditional way,
    // so there is not need for a "root" directory
    return -EINVAL;
}

static int
pipe_fs_mount_load_node(
        struct fs_mount *mnt,
        size_t index,
	struct fs_node *fs_node)
{
    int res;

    // We assume the upper level will never try to load a node
    // which already exists, so we can just let them give us a
    // unique index (TODO: This might not be a safe assumption long term)

    dprintk("pipe_fs_mount_load_node(%ld)\n", index);

    struct pipe *pipe = kmalloc(sizeof(struct pipe), KM_KERNEL);
    if(pipe == NULL) {
        wprintk("Failed to allocate pipefs node: Out of Memory\n");
        return res;
    }

    pipe->buflen = DEFAULT_PIPE_BUFSIZE;
    pipe->buffer = kmalloc(pipe->buflen, KM_KERNEL);
    if(pipe->buffer == NULL) {
        wprintk("Failed to allocate pipefs node buffer: Out of Memory\n");
        kfree(pipe);
        return res;
    }
    pipe->head = 0;
    pipe->tail = 0;
    spinlock_init(&pipe->lock);

    fs_node->backing.node_ops = &pipe_fs_node_ops;
    fs_node->backing.file_ops = &pipe_fs_file_ops;
    fs_node->backing.priv_state = pipe;

    res = waitqueue_init(&pipe->read_queue);
    if(res) {
        wprintk("Failed to init pipefs node read queue: %s\n",
                errnostr(res));
        kfree(pipe);
        return res;
    }

    res = waitqueue_init(&pipe->write_queue);
    if(res) {
        wprintk("Failed to init pipefs node write queue: %s\n",
                errnostr(res));
        waitqueue_disable(&pipe->read_queue);
        wake_all(&pipe->read_queue);
        waitqueue_deinit(&pipe->read_queue);
        kfree(pipe);
        return res;
    }

    return 0;
}

static int
pipe_fs_mount_unload_node(
        struct fs_mount *mnt,
	size_t index,
        struct fs_node *fs_node)
{
    struct pipe *pipe = fs_node->backing.priv_state;

    waitqueue_disable(&pipe->read_queue);
    wake_all(&pipe->read_queue);
    waitqueue_deinit(&pipe->read_queue);

    waitqueue_disable(&pipe->write_queue);
    wake_all(&pipe->write_queue);
    waitqueue_deinit(&pipe->write_queue);

    kfree(pipe->buffer);
    kfree(pipe);

    return 0;
}

static struct fs_mount_ops
pipe_fs_mount_ops =
{
    .root_index = pipe_fs_root_index,

    .load_node = pipe_fs_mount_load_node,
    .unload_node = pipe_fs_mount_unload_node,

    .sync = fs_mount_nop_sync,
};

static struct fs_mount pipe_fs_mount;

static int
pipefs_init(void)
{
    return init_fs_mount_struct(
            &pipe_fs_mount,
            &pipe_fs_mount_ops);
}
declare_init_desc(fs, pipefs_init, "Creating PipeFS");

// This is awful and I hate it but assume we will never overflow
// 2^64 pipes between reboots.
static uint64_t next_pipe_index = 0;
DEFINE_LOCAL_THREAD_LOCK(next_pipe_index_lock);

struct fs_node *
pipe_fs_get_anon_pipe(void)
{
    next_pipe_index_lock_acquire();
    uint64_t index = next_pipe_index;
    next_pipe_index++;
    next_pipe_index_lock_release();

    struct fs_node *node = fs_mount_get_node(
            &pipe_fs_mount,
            index);
    if(node == NULL) {
        wprintk("pipe_fs_get_anon_pipe: fs_mount_get_node returned NULL!\n");
        return NULL;
    }

    return node;
}

