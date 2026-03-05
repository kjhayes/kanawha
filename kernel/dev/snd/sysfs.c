#include <kanawha/dev/snd.h>
#include <kanawha/parse.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/sysfs/vfs.h>
#include <kanawha/uapi/snd.h>

struct snd_dev_fs_node
{
    struct snd_dev *dev;

    struct vfs_node stream_vfs_node;
    struct vfs_node mode_info_vfs_node;
    size_t mode_info_vfs_current_mode;
};

static struct vfs_mount *snd_dev_fs_mount = NULL;

// stream vfs node

static int
snd_dev_stream_setattr(struct fs_node *node, int attr, size_t value)
{
    struct snd_dev_fs_node *sndfs = container_of(node->backing.priv_state,
                                                 struct snd_dev_fs_node,
                                                 stream_vfs_node);
    DEBUG_ASSERT(KERNEL_ADDR(sndfs));
    DEBUG_ASSERT(KERNEL_ADDR(sndfs->dev));

    switch(attr)
    {
    case FS_NODE_ATTR_DATA_SIZE:
        if(value == 0)
        {
            // Ignore it
            return 0;
        }
        else
        {
            return -EINVAL;
        }
    default:
        return -EINVAL;
    }
}

static int
snd_dev_stream_getattr(struct fs_node *node, int attr, size_t *value)
{
    int res;

    struct snd_dev_fs_node *sndfs = container_of(node->backing.priv_state,
                                                 struct snd_dev_fs_node,
                                                 stream_vfs_node);
    DEBUG_ASSERT(KERNEL_ADDR(sndfs));
    DEBUG_ASSERT(KERNEL_ADDR(sndfs->dev));

    switch(attr)
    {
    case FS_NODE_ATTR_DATA_SIZE:
        return 0;
    default:
        return -EINVAL;
    }
}

static ssize_t
snd_dev_stream_read(struct file *file,
                    void *buffer,
                    ssize_t buflen,
                    unsigned long flags)
{
    // printk("snd_dev_stream_read!\n");
    return 0;
}

static ssize_t
snd_dev_stream_write(struct file *file,
                     void *buffer,
                     ssize_t buflen,
                     unsigned long flags)
{
    // printk("snd_dev_stream_write!\n");

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL)
    {
        return -ENXIO;
    }
    struct snd_dev_fs_node *sndfs = container_of(fs_node->backing.priv_state,
                                                 struct snd_dev_fs_node,
                                                 stream_vfs_node);

    unsigned long snd_flags = 0x0;
    if(flags & FS_FILE_WRITE_NON_BLOCKING)
    {
        snd_flags |= SND_DEV_WRITE_SAMPLES_NON_BLOCKING;
    }

    ssize_t written;
    written = snd_dev_write_samples(sndfs->dev, buffer, buflen, snd_flags);

    return written;
}

static struct fs_node_ops snd_dev_stream_fs_node_ops = {
    .getattr = snd_dev_stream_getattr,
    .setattr = snd_dev_stream_setattr,
    .flush = fs_node_flush_nop,

    .lookup = vfs_dir_lookup,
};
FS_NODE_OPS_INIT_UNDEF(snd_dev_stream_fs_node_ops);
static struct fs_file_ops snd_dev_stream_fs_file_ops = {
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
snd_dev_mode_info_fs_node_setattr(struct fs_node *node, int attr, size_t value)
{
    struct snd_dev_fs_node *sndfs = container_of(node->backing.priv_state,
                                                 struct snd_dev_fs_node,
                                                 mode_info_vfs_node);
    DEBUG_ASSERT(KERNEL_ADDR(sndfs));
    DEBUG_ASSERT(KERNEL_ADDR(sndfs->dev));

    switch(attr)
    {
    case FS_NODE_ATTR_DATA_SIZE:
        if(value == 0)
        {
            // Ignore it
            return 0;
        }
        else
        {
            return -EINVAL;
        }
    default:
        return -EINVAL;
    }
}

static int
snd_dev_mode_info_fs_node_getattr(struct fs_node *node, int attr, size_t *value)
{
    int res;

    struct snd_dev_fs_node *sndfs = container_of(node->backing.priv_state,
                                                 struct snd_dev_fs_node,
                                                 mode_info_vfs_node);
    DEBUG_ASSERT(KERNEL_ADDR(sndfs));
    DEBUG_ASSERT(KERNEL_ADDR(sndfs->dev));

    struct snd_mode_info *info =
        snd_dev_get_mode_info(sndfs->dev, sndfs->mode_info_vfs_current_mode);

    switch(attr)
    {
    case FS_NODE_ATTR_DATA_SIZE:
        if(info == NULL)
        {
            *value = 0;
        }
        else
        {
            *value = sizeof(struct snd_mode_info);
        }
        return 0;
    default:
        return -EINVAL;
    }
}

static ssize_t
snd_dev_mode_info_fs_file_write(struct file *file,
                                void *buf,
                                ssize_t buflen,
                                unsigned long flags)
{
    int res;

    struct fs_node *node = fs_path_get_fs_node(file->path);
    if(node == NULL)
    {
        return -ENXIO;
    }

    struct snd_dev_fs_node *sndfs = container_of(node->backing.priv_state,
                                                 struct snd_dev_fs_node,
                                                 mode_info_vfs_node);
    DEBUG_ASSERT(KERNEL_ADDR(sndfs));
    DEBUG_ASSERT(KERNEL_ADDR(sndfs->dev));

    if(file->seek_offset != 0)
    {
        return 0;
    }

    if(buflen > 0)
    {
    }

    char str_buf[buflen + 1];
    memcpy(str_buf, buf, buflen);
    str_buf[buflen] = '\0';

    unsigned long value = parse_unsigned_long(str_buf, 0);
    sndfs->mode_info_vfs_current_mode = value;

    return buflen;
}

static ssize_t
snd_dev_mode_info_fs_file_read(struct file *file,
                               void *buf,
                               ssize_t buflen,
                               unsigned long flags)
{
    DEBUG_ASSERT(KERNEL_ADDR(file));
    DEBUG_ASSERT(KERNEL_ADDR(file->path));

    struct fs_node *node = fs_path_get_fs_node(file->path);
    if(node == NULL)
    {
        return -ENXIO;
    }
    struct snd_dev_fs_node *sndfs = container_of(node->backing.priv_state,
                                                 struct snd_dev_fs_node,
                                                 mode_info_vfs_node);

    DEBUG_ASSERT(KERNEL_ADDR(sndfs));
    DEBUG_ASSERT(KERNEL_ADDR(sndfs->dev));

    struct snd_mode_info *info =
        snd_dev_get_mode_info(sndfs->dev, sndfs->mode_info_vfs_current_mode);
    if(info == NULL)
    {
        if(file->seek_offset == 0)
        {
            return 0; // Nothing to read
        }
        else
        {
            return -EINVAL;
        }
    }

    size_t size = sizeof(struct snd_mode_info);
    if(file->seek_offset > size)
    {
        return -EINVAL;
    }

    size_t room_left = size - file->seek_offset;
    if(room_left > buflen)
    {
        room_left = buflen;
    }

    memcpy(buf, info, room_left);

    return room_left;
}
static struct fs_node_ops snd_dev_mode_info_fs_node_ops = {
    .setattr = snd_dev_mode_info_fs_node_setattr,
    .getattr = snd_dev_mode_info_fs_node_getattr,
    .flush = fs_node_flush_nop,
};
FS_NODE_OPS_INIT_UNDEF(snd_dev_mode_info_fs_node_ops);

static struct fs_file_ops snd_dev_mode_info_fs_file_ops = {
    .read = snd_dev_mode_info_fs_file_read,
    .write = snd_dev_mode_info_fs_file_write,
    .seek = fs_file_paged_seek,
};
FS_FILE_OPS_INIT_UNDEF(snd_dev_mode_info_fs_file_ops);

static int
snd_dev_fs_probe_snd_dev(struct snd_dev *dev)
{
    return 0;
}

static int
snd_dev_fs_receive_snd_dev(struct snd_dev *dev)
{
    int res;

    struct snd_dev_fs_node *sndfs = kmalloc(sizeof(*sndfs), KM_KERNEL);
    if(sndfs == NULL)
    {
        return -ENOMEM;
    }
    memset(sndfs, 0, sizeof(*sndfs));

    sndfs->dev = dev;
    sndfs->mode_info_vfs_current_mode = snd_dev_get_mode(sndfs->dev);

    sndfs->stream_vfs_node.fs_node_ops = &snd_dev_stream_fs_node_ops;
    sndfs->stream_vfs_node.fs_file_ops = &snd_dev_stream_fs_file_ops;
    res = vfs_mount_insert_node_and_link_root(snd_dev_fs_mount,
                                              &sndfs->stream_vfs_node,
                                              snd_dev_get_name(dev));
    if(res)
    {
        kfree(sndfs);
        return res;
    }

    size_t mode_info_inode;
    sndfs->mode_info_vfs_node.fs_node_ops = &snd_dev_mode_info_fs_node_ops;
    sndfs->mode_info_vfs_node.fs_file_ops = &snd_dev_mode_info_fs_file_ops;
    res = vfs_mount_insert_node(snd_dev_fs_mount,
                                &sndfs->mode_info_vfs_node,
                                &mode_info_inode);
    if(res)
    {
        vfs_mount_unlink_root(snd_dev_fs_mount, snd_dev_get_name(dev));
        vfs_node_unlink_all(&sndfs->stream_vfs_node);
        kfree(sndfs);
        return res;
    }
    res = vfs_node_link(&sndfs->stream_vfs_node, "mode_info", mode_info_inode);
    if(res)
    {
        vfs_mount_remove_node(snd_dev_fs_mount, &sndfs->mode_info_vfs_node);
        vfs_mount_unlink_root(snd_dev_fs_mount, snd_dev_get_name(dev));
        vfs_node_unlink_all(&sndfs->stream_vfs_node);
        vfs_mount_remove_node(snd_dev_fs_mount, &sndfs->stream_vfs_node);
        kfree(sndfs);
        return res;
    }

    return 0;
}

static int
snd_dev_fs_revoke_snd_dev(struct snd_dev *dev)
{
    eprintk("Tried to unregister snd_dev from sysfs! (UNIMPL)\n");
    return -EUNIMPL;
}

static struct snd_dev_owner snd_dev_fs_owner = {
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
    if(mnt == NULL)
    {
        eprintk("Failed to create VFS mount for sysfs framebuffers!\n");
        return -ENOMEM;
    }

    snd_dev_fs_mount = mnt;

    res = register_snd_dev_owner(&snd_dev_fs_owner);
    if(res)
    {
        vfs_mount_destroy(mnt);
        return res;
    }

    res = sysfs_register_mount(&snd_dev_fs_mount->fs_mount, "snddev");
    if(res)
    {
        unregister_snd_dev_owner(&snd_dev_fs_owner);
        snd_dev_fs_mount = NULL;
        vfs_mount_destroy(mnt);
        return res;
    }

    return 0;
}
declare_init_desc(fs, snd_dev_init_fs_mount, "Registering snddev Sysfs Mount");
