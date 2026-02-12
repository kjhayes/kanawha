#include <kanawha/dev/snd.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/uapi/snd.h>

struct snd_dev_fs_node {
    struct snd_dev *dev;

    struct vfs_node stream_vfs_node;
};

static struct vfs_mount *snd_dev_fs_mount = NULL;

// stream vfs node

static ssize_t
snd_dev_stream_read(
        struct file *file,
        void *buffer,
        ssize_t buflen,
        unsigned long flags)
{
    printk("snd_dev_stream_read!\n");
    return 0;
}


static ssize_t
snd_dev_stream_write(
        struct file *file,
        void *buffer,
        ssize_t buflen,
        unsigned long flags)
{
    printk("snd_dev_stream_write!\n");

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -ENXIO;
    }
    struct snd_dev_fs_node *sndfs =
        container_of(fs_node->backing.priv_state, struct snd_dev_fs_node, stream_vfs_node);

    unsigned long snd_flags = 0x0;
    if(flags & FS_FILE_WRITE_NON_BLOCKING) {
        snd_flags |= SND_DEV_WRITE_SAMPLES_NON_BLOCKING;
    }

    ssize_t written;
    written = snd_dev_write_samples(
            sndfs->dev,
            buffer,
            buflen,
            snd_flags);

    return written;
}

static struct fs_node_ops
snd_dev_stream_fs_node_ops = {
    .lookup = vfs_dir_lookup,
};
FS_NODE_OPS_INIT_UNDEF(snd_dev_stream_fs_node_ops);
static struct fs_file_ops
snd_dev_stream_fs_file_ops =
{
    .read = snd_dev_stream_read,
    .write = snd_dev_stream_write,
    .flush = fs_file_nop_flush,
    .seek = fs_file_seek_pinned_zero,

    .dir_begin = vfs_dir_begin,
    .dir_next = vfs_dir_next,
    .dir_readattr = vfs_dir_readattr,
    .dir_readname = vfs_dir_readname,
};
FS_FILE_OPS_INIT_UNDEF(snd_dev_stream_fs_file_ops);

static int
snd_dev_fs_probe_snd_dev(
        struct snd_dev *dev)
{
    return 0;
}

static int
snd_dev_fs_receive_snd_dev(
        struct snd_dev *dev)
{
    int res;

    struct snd_dev_fs_node *sndfs = kmalloc(sizeof(*sndfs), KM_KERNEL);
    if(sndfs == NULL) {
        return -ENOMEM;
    }
    memset(sndfs, 0, sizeof(*sndfs));

    sndfs->dev = dev;

    sndfs->stream_vfs_node.fs_node_ops = &snd_dev_stream_fs_node_ops;
    sndfs->stream_vfs_node.fs_file_ops = &snd_dev_stream_fs_file_ops;
    res = vfs_mount_insert_node_and_link_root(
            snd_dev_fs_mount,
            &sndfs->stream_vfs_node,
            snd_dev_get_name(dev));
    if(res) {
        kfree(sndfs);
        return res;
    }

    return 0;
}

static int
snd_dev_fs_revoke_snd_dev(
        struct snd_dev *dev)
{
    eprintk("Tried to unregister snd_dev from sysfs! (UNIMPL)\n");
    return -EUNIMPL;
}

static struct snd_dev_owner
snd_dev_fs_owner = {
    .probe = snd_dev_fs_probe_snd_dev,
    .receive = snd_dev_fs_receive_snd_dev,
    .revoke = snd_dev_fs_revoke_snd_dev,
};

static int
snd_dev_init_fs_mount(void)
{
    int res;
    struct vfs_mount *mnt;
    mnt = vfs_mount_create();
    if(mnt == NULL) {
        eprintk("Failed to create VFS mount for sysfs framebuffers!\n");
        return -ENOMEM;
    }

    snd_dev_fs_mount = mnt;

    res = register_snd_dev_owner(&snd_dev_fs_owner);
    if(res) {
        vfs_mount_destroy(mnt);
        return res;
    }

    res = sysfs_register_mount(
            &snd_dev_fs_mount->fs_mount,
            "snddev");
    if(res) {
        unregister_snd_dev_owner(&snd_dev_fs_owner);
        snd_dev_fs_mount = NULL;
        vfs_mount_destroy(mnt);
        return res;
    }

    return 0;
}
declare_init_desc(fs, snd_dev_init_fs_mount, "Registering snddev Sysfs Mount");
