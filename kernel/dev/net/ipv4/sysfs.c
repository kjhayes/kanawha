
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

static struct fs_node_ops ipv4_dev_fs_node_ops;
static struct fs_file_ops ipv4_dev_fs_file_ops;

static int
ipv4_dev_fs_probe_ipv4_dev(
        struct ipv4_dev *dev)
{
    return 0;
}

static int
ipv4_dev_fs_receive_ipv4_dev(
        struct ipv4_dev *dev)
{
    int res;

    struct ipv4_dev_fs_node *edfs = kzmalloc(sizeof(*edfs), KM_KERNEL);
    if(edfs == NULL) {
        return -ENOMEM;
    }

    edfs->dev = dev;

    edfs->vfs_node.fs_file_ops = &ipv4_dev_fs_file_ops;
    edfs->vfs_node.fs_node_ops = &ipv4_dev_fs_node_ops;

    res = vfs_mount_insert_node_and_link_root(
            ipv4_dev_fs_mount,
            &edfs->vfs_node,
            ipv4_dev_get_name(dev));
    if(res) {
        kfree(edfs);
        return res;
    }

    // TODO Remove This Test PING
    res = ipv4_dev_send_icmp_ping(dev, IPV4_ADDR_LOOPBACK, IPV4_ADDR_LOCAL_BROADCAST);
    if(res) {
        wprintk("Failed to send ICMP ping (%s)\n", errnostr(res));
    }

    return 0;
}

static int
ipv4_dev_fs_revoke_ipv4_dev(
        struct ipv4_dev *dev)
{
    wprintk("Tried to unregister ipv4_dev from sysfs! (UNIMPL)\n");
    return -EUNIMPL;
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
};
FS_NODE_OPS_INIT_UNDEF(ipv4_dev_fs_node_ops);

static struct fs_file_ops
ipv4_dev_fs_file_ops =
{
    .write = ipv4_dev_fs_file_write,
    .seek = fs_file_seek_pinned_zero,

    .dir_next = vfs_dir_next,
    .dir_begin = vfs_dir_begin,
    .dir_readattr = vfs_dir_readattr,
    .dir_readname = vfs_dir_readname,
};
FS_FILE_OPS_INIT_UNDEF(ipv4_dev_fs_file_ops);

static struct ipv4_dev_owner
ipv4_dev_fs_owner = {
    .probe = ipv4_dev_fs_probe_ipv4_dev,
    .receive = ipv4_dev_fs_receive_ipv4_dev,
    .revoke = ipv4_dev_fs_revoke_ipv4_dev,
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

    res = register_ipv4_dev_owner(&ipv4_dev_fs_owner);
    if(res) {
        vfs_mount_destroy(mnt);
        return res;
    }

    res = sysfs_register_mount(&ipv4_dev_fs_mount->fs_mount, "ipv4dev");
    if(res) {
        unregister_ipv4_dev_owner(&ipv4_dev_fs_owner);
        vfs_mount_destroy(mnt);
        return res;
    }

    return 0;
}
declare_init_desc(fs, ipv4_dev_init_fs_mount, "Registering IPv4 Sysfs Mount");

