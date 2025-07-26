
#include <kanawha/dev/net/eth.h>
#include <kanawha/stree.h>
#include <kanawha/lock.h>
#include <kanawha/stddef.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/parse.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/net/ethernet.h>
#include <kanawha/endian.h>

struct eth_dev_fs_node
{
    struct eth_dev *dev;
    struct vfs_node vfs_node;
};

static struct vfs_mount *eth_dev_fs_mount = NULL;
static struct eth_dev_registry_hook *eth_dev_fs_hook = NULL;

static struct fs_node_ops eth_dev_fs_node_ops;
static struct fs_file_ops eth_dev_fs_file_ops;

static void
eth_dev_fs_on_register(
        struct eth_dev *dev)
{
    int res;

    struct eth_dev_fs_node *edfs = kmalloc(sizeof(*edfs));
    if(edfs == NULL) {
        return;
    }
    memset(edfs, 0, sizeof(*edfs));

    edfs->dev = dev;

    edfs->vfs_node.fs_node.unload = NULL;
    edfs->vfs_node.fs_node.file_ops = &eth_dev_fs_file_ops;
    edfs->vfs_node.fs_node.node_ops = &eth_dev_fs_node_ops;

    res = vfs_mount_insert_node_and_link_root(
            eth_dev_fs_mount,
            &edfs->vfs_node,
            eth_dev_get_name(dev));
    if(res) {
        kfree(edfs);
        return;
    }

    return;
}

static void
eth_dev_fs_on_unregister(
        struct eth_dev *dev)
{
    panic("Tried to unregister eth_dev from sysfs! (UNIMPL)\n");
}

static ssize_t 
eth_dev_fs_file_read(
        struct file *file,
        void *buffer,
        ssize_t amount,
        unsigned long flags)
{
    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -ENXIO;
    }

    struct eth_dev_fs_node *edfs =
        container_of(fs_node, struct eth_dev_fs_node, vfs_node.fs_node);

    if(flags & FS_FILE_READ_NON_BLOCKING) {
        return -EWOULDBLOCK;
    }

    size_t amt_read = 0;

    // TODO

    return amt_read;
}

static ssize_t 
eth_dev_fs_file_write(
        struct file *file,
        void *buffer,
        ssize_t amount,
        unsigned long flags)
{
    int res;

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -ENXIO;
    }

    struct eth_dev_fs_node *edfs =
        container_of(fs_node, struct eth_dev_fs_node, vfs_node.fs_node);

    if(flags & FS_FILE_READ_NON_BLOCKING) {
        return -EWOULDBLOCK;
    }

    if(amount < sizeof(struct eth_frame_hdr)) {
        return -EINVAL;
    }

    {
        struct eth_frame_hdr *hdr = buffer;

        struct eth_mac_addr src;
        struct eth_mac_addr dst;

        src.raw = hdr->src_addr;
        dst.raw = hdr->dst_addr;

        eth_type_t type = betoh16(hdr->type);

        // TODO (Do some basic validation of the header)
    }

    struct eth_frame *frame =
        eth_dev_alloc_frame(
            edfs->dev,
            amount,
            0);

    if(frame == NULL) {
        return -ENOMEM;
    }

    memcpy(frame->data, buffer, amount);

    res = eth_dev_send_frame(
            edfs->dev,
            frame);

    // drop the packet regardless of success or failure to send
    int drop_res = eth_dev_drop_frame(edfs->dev, frame);
    if(drop_res) {
        wprintk("Potential Memory Leak: eth_dev sysfs failed to drop allocated ethernet frame! (drop-err=%s)\n",
                 errnostr(drop_res));
    }

    // from eth_dev_send_frame
    if(res) {
        return res;
    }

    return amount;
}

static struct fs_node_ops
eth_dev_fs_node_ops =
{
    .lookup = vfs_dir_lookup,

    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_write_page,
    .load_page = fs_node_cannot_load_page,
    .unload_page = fs_node_cannot_unload_page,
    .mkfile = fs_node_cannot_mkfile,
    .mkdir = fs_node_cannot_mkdir,
    .link = fs_node_cannot_link,
    .symlink = fs_node_cannot_symlink,
    .unlink = fs_node_cannot_unlink,
    .flush = fs_node_flush_nop,
    .setattr = fs_node_cannot_setattr,
    .getattr = fs_node_cannot_getattr,
};

static struct fs_file_ops
eth_dev_fs_file_ops =
{
    .read = eth_dev_fs_file_read,
    .write = eth_dev_fs_file_write,
    .flush = fs_file_cannot_flush,
    .seek = fs_file_seek_pinned_zero,
    .poll = fs_file_cannot_poll,

    .dir_next = vfs_dir_next,
    .dir_begin = vfs_dir_begin,
    .dir_readattr = vfs_dir_readattr,
    .dir_readname = vfs_dir_readname,
};

static int
eth_dev_fs_recv_callback(
        struct eth_dev *dev,
        struct eth_frame *buffer,
        size_t buflen,
        void *priv_state)
{
    struct edfs *edfs = priv_state;

    printk("Ethernet Device (%s) Received Packet of Length 0x%lx\n",
            eth_dev_get_name(dev),
            buflen);

    return 0;
}

static int
eth_dev_init_fs_mount(void)
{
    int res;

    struct vfs_mount *mnt;
    mnt = vfs_mount_create();
    if(mnt == NULL) {
        eprintk("Failed to create eth_dev VFS mount!\n");
        return -ENOMEM;
    }

    eth_dev_fs_mount = mnt;

    struct eth_dev_registry_hook *hook;
    hook = hook_eth_dev_registry(
            eth_dev_fs_on_register,
            eth_dev_fs_on_unregister);
    if(hook == NULL) {
        eth_dev_fs_mount = NULL;
        vfs_mount_destroy(mnt);
        return -ENOMEM;
    }

    res = sysfs_register_mount(&eth_dev_fs_mount->fs_mount, "ethdev");
    if(res) {
        eth_dev_fs_hook = NULL;
        unhook_eth_dev_registry(hook);
        eth_dev_fs_mount = NULL;
        vfs_mount_destroy(mnt);
        return res;
    }

    return 0;
}
declare_init_desc(fs, eth_dev_init_fs_mount, "Registering Ethernet Sysfs Mount");

