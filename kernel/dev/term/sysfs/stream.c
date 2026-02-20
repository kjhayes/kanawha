
#include <kanawha/dev/term/sysfs.h>
#include <kanawha/dev/term.h>

#include <kanawha/types.h>
#include <kanawha/init.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/lock.h>
#include <kanawha/kmalloc.h>
#include <kanawha/fs/type.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/waitqueue.h>
#include <kanawha/uapi/poll.h>

static ssize_t 
term_dev_stream_fs_file_read(
        struct file *file,
        void *buffer,
        ssize_t amount,
        unsigned long flags)
{
    int res;

    struct term_dev *dev = term_dev_from_file(file, stream_vfs_node);

    int can_block = !(flags & FS_FILE_READ_NON_BLOCKING);

    ssize_t amt_read;
    while(1) {
        amt_read = term_driver_read_nonblocking(dev, buffer, amount);
        DEBUG_ASSERT(amt_read <= amount);
        if(amt_read < 0) {
            if(amt_read == -EWOULDBLOCK && can_block) {
		        // amt_read == -EWOULDBLOCK and we can block
                res = wait_on(&dev->read_wq);
                if(res) {
                    return res;
                }
		        continue;
            } else {
		        // Return the error
		        return amt_read;
	        }
	    } else {
	        break;
	    }
    }

    return amt_read;
}

static ssize_t
term_dev_stream_fs_file_write(
        struct file *file,
        void *buffer,
        ssize_t amount,
        unsigned long flags)
{
    int res;

    struct term_dev *dev = term_dev_from_file(file, stream_vfs_node);

    int can_block = !(flags & FS_FILE_WRITE_NON_BLOCKING);

    ssize_t amt_written = 0;
    while(1) {
        amt_written = term_driver_write_nonblocking(dev, buffer, amount);
        DEBUG_ASSERT(amt_written <= amount);
        if(amt_written < 0) {
            if(amt_written == -EWOULDBLOCK && can_block) {
                res = wait_on(&dev->write_wq);
                if(res) {
                    return res;
                }
                continue;
            } else {
		        // Return the error
		        return amt_written;
	        }
	    } else {
	        break;
	    }
    }

    return amt_written;
}

static int
term_dev_stream_fs_file_flush(
        struct file *file,
        unsigned long flags)
{
    struct term_dev *dev = term_dev_from_file(file, stream_vfs_node);
    return term_dev_flush(dev);
}

static int
term_dev_stream_fs_node_setattr(
        struct fs_node *fs_node,
        int attr,
        size_t value)
{
    struct term_dev *dev = term_dev_from_node(fs_node, stream_vfs_node);

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            // We'll accept any value here and ignore it
            return 0;
    }
    return -EINVAL;
}

static int
term_dev_stream_fs_node_getattr(
        struct fs_node *fs_node,
        int attr,
        size_t *value)
{
    struct term_dev *dev = term_dev_from_node(fs_node, stream_vfs_node);

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            *value = 0;
            return 0;
    }

    return -EINVAL;
}

static int
term_dev_stream_fs_file_poll(
	struct file *file,
	unsigned long watching,
	unsigned long *triggered)
{
    int res;
    struct term_dev *dev = term_dev_from_file(file, stream_vfs_node);

    *triggered = 0;

    if(watching & POLL_READ_NONBLOCKING) {
	if(!term_driver_input_empty(dev)) {
	    *triggered |= POLL_READ_NONBLOCKING; 
	}
	if(!term_driver_output_full(dev)) {
	    *triggered |= POLL_WRITE_NONBLOCKING;
	}
    }

    return 0;
}

static struct fs_node_ops term_dev_stream_fs_node_ops =
{
    .flush = fs_node_flush_nop,
    .setattr = term_dev_stream_fs_node_setattr,
    .getattr = term_dev_stream_fs_node_getattr,

    .lookup = vfs_dir_lookup,
};
FS_NODE_OPS_INIT_UNDEF(term_dev_stream_fs_node_ops);

static struct fs_file_ops term_dev_stream_fs_file_ops =
{
    .read = term_dev_stream_fs_file_read,
    .write = term_dev_stream_fs_file_write,
    .flush = term_dev_stream_fs_file_flush,
    .poll = term_dev_stream_fs_file_poll,

    .dir_begin = vfs_dir_begin,
    .dir_next = vfs_dir_next,
    .dir_readattr = vfs_dir_readattr,
    .dir_readname = vfs_dir_readname,
};
FS_FILE_OPS_INIT_UNDEF(term_dev_stream_fs_file_ops);

int term_dev_fs_node_init_stream(struct term_dev_fs_node *node)
{
    node->stream_vfs_node.fs_node_ops = &term_dev_stream_fs_node_ops;
    node->stream_vfs_node.fs_file_ops = &term_dev_stream_fs_file_ops;

    size_t inode;
    vfs_mount_insert_node(term_dev_fs_mount, &node->stream_vfs_node, &inode);

    return 0;
}
int term_dev_fs_node_deinit_stream(struct term_dev_fs_node *node)
{
    vfs_mount_remove_node(term_dev_fs_mount, &node->stream_vfs_node);
    return 0;
}

