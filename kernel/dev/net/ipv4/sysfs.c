
#include <kanawha/dev/net/ipv4.h>
#include <kanawha/stree.h>
#include <kanawha/lock.h>
#include <kanawha/stddef.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/parse.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/net/ip.h>
#include <kanawha/endian.h>

#include <kanawha/net/icmp.h>

struct ipv4_dev_fs_node
{
    struct ipv4_dev *dev;
    struct vfs_node vfs_node;
};

static struct vfs_mount *ipv4_dev_fs_mount = NULL;
static struct ipv4_dev_registry_hook *ipv4_dev_fs_hook = NULL;

static struct fs_node_ops ipv4_dev_fs_node_ops;
static struct fs_file_ops ipv4_dev_fs_file_ops;

static void
ipv4_dev_fs_on_register(
        struct ipv4_dev *dev)
{
    int res;

    struct ipv4_dev_fs_node *edfs = kmalloc(sizeof(*edfs));
    if(edfs == NULL) {
        return;
    }
    memset(edfs, 0, sizeof(*edfs));

    edfs->dev = dev;

    edfs->vfs_node.fs_file_ops = &ipv4_dev_fs_file_ops;
    edfs->vfs_node.fs_node_ops = &ipv4_dev_fs_node_ops;

    res = vfs_mount_insert_node_and_link_root(
            ipv4_dev_fs_mount,
            &edfs->vfs_node,
            ipv4_dev_get_name(dev));
    if(res) {
        kfree(edfs);
        return;
    }

    // TODO Remove This Test PING
    res = ipv4_dev_send_icmp_ping(dev, IPV4_ADDR_LOOPBACK, IPV4_ADDR_LOCAL_BROADCAST);
    if(res) {
        wprintk("Failed to send ICMP ping (%s)\n", errnostr(res));
    }

    return;
}

static void
ipv4_dev_fs_on_unregister(
        struct ipv4_dev *dev)
{
    panic("Tried to unregister ipv4_dev from sysfs! (UNIMPL)\n");
}

static ssize_t 
ipv4_dev_fs_file_write(
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

    struct ipv4_dev_fs_node *idfs =
        container_of(fs_node->backing.priv_state, struct ipv4_dev_fs_node, vfs_node);

    if(flags & FS_FILE_READ_NON_BLOCKING) {
        return -EWOULDBLOCK;
    }

    if(amount < sizeof(struct ipv4_pkt_hdr)) {
        return -EINVAL;
    }

    {
        struct ipv4_pkt_hdr *hdr = buffer;

        // TODO (Do some basic validation of the header)
    }

    struct ipv4_packet *pkt =
        ipv4_dev_alloc_packet(
            idfs->dev,
            amount,
            0);

    if(pkt == NULL) {
        return -ENOMEM;
    }

    memcpy(pkt->data, buffer, amount);

    res = ipv4_dev_send_packet(
            idfs->dev,
            pkt);

    // drop the packet regardless of success or failure to send
    int drop_res = ipv4_dev_drop_packet(idfs->dev, pkt);
    if(drop_res) {
        wprintk("Potential Memory Leak: ipv4_dev sysfs failed to drop allocated packet! (drop-err=%s)\n",
                 errnostr(drop_res));
    }

    // from ipv4_dev_send_packet
    if(res) {
        return res;
    }

    return amount;
}

static struct fs_node_ops
ipv4_dev_fs_node_ops =
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
ipv4_dev_fs_file_ops =
{
    .write = ipv4_dev_fs_file_write,
    .read = fs_file_cannot_read,

    .flush = fs_file_cannot_flush,
    .seek = fs_file_seek_pinned_zero,
    .poll = fs_file_cannot_poll,

    .dir_next = vfs_dir_next,
    .dir_begin = vfs_dir_begin,
    .dir_readattr = vfs_dir_readattr,
    .dir_readname = vfs_dir_readname,
};

static int
ipv4_dev_init_fs_mount(void)
{
    int res;

    struct vfs_mount *mnt;
    mnt = vfs_mount_create();
    if(mnt == NULL) {
        eprintk("Failed to create ipv4_dev VFS mount!\n");
        return -ENOMEM;
    }

    ipv4_dev_fs_mount = mnt;

    struct ipv4_dev_registry_hook *hook;
    hook = hook_ipv4_dev_registry(
            ipv4_dev_fs_on_register,
            ipv4_dev_fs_on_unregister);
    if(hook == NULL) {
        ipv4_dev_fs_mount = NULL;
        vfs_mount_destroy(mnt);
        return -ENOMEM;
    }

    res = sysfs_register_mount(&ipv4_dev_fs_mount->fs_mount, "ipv4");
    if(res) {
        ipv4_dev_fs_hook = NULL;
        unhook_ipv4_dev_registry(hook);
        ipv4_dev_fs_mount = NULL;
        vfs_mount_destroy(mnt);
        return res;
    }

    return 0;
}
declare_init_desc(fs, ipv4_dev_init_fs_mount, "Registering IPv4 Sysfs Mount");

