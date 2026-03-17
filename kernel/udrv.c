
#include <kanawha/fs/file.h>
#include <kanawha/fs/node.h>
#include <kanawha/uapi/poll.h>
#include <kanawha/udrv.h>

static struct vfs_mount *udrv_fs_mount = NULL;

static struct fs_node_ops udrv_mount_fs_node_ops;
static struct fs_file_ops udrv_mount_fs_file_ops;

static struct fs_node_ops udrv_dev_fs_node_ops;
static struct fs_file_ops udrv_dev_fs_file_ops;

struct udrv_user_pkt
{
    ilist_node_t queue_node;
    size_t pktlen;
    struct udrv_pkt pkt;
};

static inline void
udrv_dev_wake_writers(struct udrv_dev *dev)
{
    wake_all(&dev->write_wq);
}
static inline void
udrv_dev_wake_readers(struct udrv_dev *dev)
{
    wake_all(&dev->read_wq);
}
static int
udrv_mount_on_register(struct udrv_mount *mnt)
{
    int res;

    if(udrv_fs_mount == NULL)
    {
        return -EDEFER;
    }

    printk("Registering User Driver Framework \"%s\"\n",
           udrv_mount_get_name(mnt));

    DEBUG_ASSERT(KERNEL_ADDR(mnt->ops));

    mnt->vfs_node.fs_node_ops = &udrv_mount_fs_node_ops;
    mnt->vfs_node.fs_file_ops = &udrv_mount_fs_file_ops;

    res = vfs_mount_insert_node_and_link_root(udrv_fs_mount,
                                              &mnt->vfs_node,
                                              udrv_mount_get_name(mnt));
    if(res)
    {
        return res;
    }

    return 0;
}

static int
udrv_mount_on_unregister(struct udrv_mount *mnt)
{
    int res;

    printk("Unregistering User Driver Framework \"%s\"\n",
           udrv_mount_get_name(mnt));

    res = vfs_mount_unlink_root(udrv_fs_mount, udrv_mount_get_name(mnt));
    if(res)
    {
        return res;
    }

    res = vfs_mount_remove_node(udrv_fs_mount, &mnt->vfs_node);
    if(res)
    {
        return res;
    }

    return 0;
}

DEFINE_REGISTRY(udrv_mount,
                registry_node,
                udrv_mount_on_register,
                udrv_mount_on_unregister);

static int
udrv_init_fs_mount(void)
{
    int res;

    struct vfs_mount *mnt;
    mnt = vfs_mount_create();
    if(mnt == NULL)
    {
        eprintk("Failed to create udrv VFS mount!\n");
        return -ENOMEM;
    }

    udrv_fs_mount = mnt;

    res = sysfs_register_mount(&udrv_fs_mount->fs_mount, "udrv");
    if(res)
    {
        udrv_fs_mount = NULL;
        vfs_mount_destroy(mnt);
        return res;
    }

    return 0;
}
declare_init_desc(fs, udrv_init_fs_mount, "Registering udrv Sysfs Mount");

// Mount Ops

static int
udrv_mount_mkfile(struct fs_node *fs_node,
                  const char *name,
                  unsigned long flags)
{
    int res;

    struct vfs_node *vfs_node = fs_node->backing.priv_state;
    struct udrv_mount *mnt =
        container_of(vfs_node, struct udrv_mount, vfs_node);

    struct udrv_dev *dev;

    dprintk("udrv_mount_mkfile\n");

    dev = udrv_mount_create(mnt, name);
    if(dev == NULL)
    {
        eprintk("udrv_mount_mkfile: udrv_mount_create returned NULL!\n");
        return -EINVAL;
    }

    dev->vfs_node.fs_node_ops = &udrv_dev_fs_node_ops;
    dev->vfs_node.fs_file_ops = &udrv_dev_fs_file_ops;
    dev->mnt = mnt;
    waitqueue_init(&dev->read_wq);
    waitqueue_init(&dev->write_wq);
    waitqueue_init(&dev->send_wq);

    {
#define NAMEBUFLEN 64
        char namebuf[NAMEBUFLEN];

        snprintk(namebuf, NAMEBUFLEN, "%s-udrv-read", name);
        namebuf[NAMEBUFLEN - 1] = '\0';
        waitqueue_name(&dev->read_wq, namebuf);

        snprintk(namebuf, NAMEBUFLEN, "%s-udrv-write", name);
        namebuf[NAMEBUFLEN - 1] = '\0';
        waitqueue_name(&dev->write_wq, namebuf);

        snprintk(namebuf, NAMEBUFLEN, "%s-udrv-send", name);
        namebuf[NAMEBUFLEN - 1] = '\0';
        waitqueue_name(&dev->send_wq, namebuf);
#undef NAMEBUFLEN
    }

    irq_lock_init(&dev->read_pkt_queue_lock);
    ilist_init(&dev->read_pkt_queue);
    dev->read_pkts_queued = 0;
    dev->max_read_pkts_queued = 1;

    size_t inode;
    res = vfs_mount_insert_node(udrv_fs_mount, &dev->vfs_node, &inode);
    if(res)
    {
        eprintk("udrv_mount_mkfile: vfs_mount_insert_node returned %s!\n",
                errnostr(res));
        udrv_mount_destroy(mnt, dev);
        return res;
    }

    res = vfs_node_link(vfs_node, name, inode);
    if(res)
    {
        eprintk("udrv_mount_mkfile: vfs_node_link returned %s!\n",
                errnostr(res));
        vfs_mount_remove_node(udrv_fs_mount, &dev->vfs_node);
        udrv_mount_destroy(mnt, dev);
        return res;
    }

    return 0;
}

static struct fs_node_ops udrv_mount_fs_node_ops = {
    .mkfile = udrv_mount_mkfile,
    .lookup = vfs_dir_lookup,
    .flush = fs_node_flush_nop,
};
FS_NODE_OPS_INIT_UNDEF(udrv_mount_fs_node_ops);

static struct fs_file_ops udrv_mount_fs_file_ops = {
    .flush = fs_file_nop_flush,
    .dir_begin = vfs_dir_begin,
    .dir_next = vfs_dir_next,
    .dir_readattr = vfs_dir_readattr,
    .dir_readname = vfs_dir_readname,
};
FS_FILE_OPS_INIT_UNDEF(udrv_mount_fs_file_ops);

// Device Ops

static ssize_t
udrv_dev_fs_file_read(struct file *file,
                      void *buffer,
                      ssize_t amount,
                      unsigned long flags)
{
    int res;

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    struct vfs_node *vfs_node = fs_node->backing.priv_state;
    struct udrv_dev *dev = container_of(vfs_node, struct udrv_dev, vfs_node);
    struct udrv_mount *mnt = dev->mnt;

    if(amount < sizeof(struct udrv_pkt))
    {
        return -EINVAL;
    }

    irq_lock_acquire(&dev->read_pkt_queue_lock);

    ilist_node_t *list_node;
    while(1)
    {
        list_node = ilist_pop_tail(&dev->read_pkt_queue);
        if(list_node == NULL)
        {
            if(flags & FS_FILE_WRITE_NON_BLOCKING)
            {
                irq_lock_release(&dev->read_pkt_queue_lock);
                return -EWOULDBLOCK;
            }
            else
            {
                int irq_flags;
                res = wait_on_irq_lock_release(&dev->read_wq,
                                               &dev->read_pkt_queue_lock,
                                               &irq_flags);
                if(res)
                {
                    return res;
                }
                enable_restore_irqs(irq_flags);
                // Could be interrupted here...
                irq_lock_acquire(&dev->read_pkt_queue_lock);
                continue;
            }
        }
        break;
    }
    dev->read_pkts_queued--;

    struct udrv_user_pkt *user_pkt =
        container_of(list_node, struct udrv_user_pkt, queue_node);

    ssize_t to_write = MIN(amount, user_pkt->pktlen);
    // printk("writing udrv packet of length=0x%lx to userspace! (buflen=0x%lx,
    // pktlen=0x%lx)\n", to_write, amount, user_pkt->pktlen);
    memcpy(buffer, &user_pkt->pkt, to_write);

    if(dev->read_pkts_queued < dev->max_read_pkts_queued)
    {
        wake_all(&dev->send_wq);
    }

    irq_lock_release(&dev->read_pkt_queue_lock);

    kfree(user_pkt);

    // printk("wrote udrv packet of length=0x%lx to userspace!\n", to_write);
    return to_write;
}

static ssize_t
udrv_dev_fs_file_write(struct file *file,
                       void *buffer,
                       ssize_t amount,
                       unsigned long flags)
{
    int res;

    dprintk("udrv_dev received packet of size 0x%lx!\n", amount);

    if(amount < sizeof(struct udrv_pkt))
    {
        wprintk("udrv_dev received packet of size 0x%lx! (too small to "
                "contain "
                "struct udrv_pkt header!)\n",
                amount);
        return -EINVAL;
    }

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    struct vfs_node *vfs_node = fs_node->backing.priv_state;
    struct udrv_dev *dev = container_of(vfs_node, struct udrv_dev, vfs_node);
    struct udrv_mount *mnt = dev->mnt;

    struct udrv_pkt *pkt = buffer;
    size_t pktlen = amount;

    while(1)
    {
        res = udrv_mount_on_recv(mnt, dev, pkt, pktlen);
        DEBUG_ASSERT_MSG(
            res <= 0,
            "udrv_mount_on_recv returned a positive value (unexpected!)");
        if(res < 0)
        {
            if(res == -EWOULDBLOCK && !(flags & FS_FILE_WRITE_NON_BLOCKING))
            {
                res = wait_on(&dev->write_wq);
                if(res)
                {
                    return res;
                }
            }
            else
            {
                return res;
            }
            continue;
        }
        else
        {
            // Successfully received packet
            break;
        }
    }

    return amount;
}

static int
udrv_dev_fs_file_poll(struct file *file, unsigned long in, unsigned long *out)
{
    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    struct vfs_node *vfs_node = fs_node->backing.priv_state;
    struct udrv_dev *dev = container_of(vfs_node, struct udrv_dev, vfs_node);
    struct udrv_mount *mnt = dev->mnt;

    *out = 0;

    if(in & POLL_READ_NONBLOCKING)
    {
        irq_lock_acquire(&dev->read_pkt_queue_lock);
        if(!ilist_empty(&dev->read_pkt_queue))
        {
            *out |= POLL_READ_NONBLOCKING;
        }
        irq_lock_release(&dev->read_pkt_queue_lock);
    }

    if(in & POLL_WRITE_NONBLOCKING)
    {
        *out |= POLL_WRITE_NONBLOCKING;
    }

    return 0;
}

static struct fs_node_ops udrv_dev_fs_node_ops = {
    .lookup = vfs_dir_lookup,
    .flush = fs_node_flush_nop,
};
FS_NODE_OPS_INIT_UNDEF(udrv_dev_fs_node_ops);

static struct fs_file_ops udrv_dev_fs_file_ops = {
    .read = udrv_dev_fs_file_read,
    .write = udrv_dev_fs_file_write,
    .poll = udrv_dev_fs_file_poll,

    .flush = fs_file_nop_flush,

    .dir_begin = vfs_dir_begin,
    .dir_next = vfs_dir_next,
    .dir_readattr = vfs_dir_readattr,
    .dir_readname = vfs_dir_readname,
};
FS_FILE_OPS_INIT_UNDEF(udrv_dev_fs_file_ops);

struct udrv_pkt *
udrv_create_user_pkt(size_t pktlen)
{
    struct udrv_user_pkt *pkt;
    if(pktlen < sizeof(struct udrv_pkt))
    {
        return NULL;
    }
    size_t datalen = pktlen - sizeof(struct udrv_pkt);
    pkt = kmalloc(sizeof(*pkt) + datalen, KM_KERNEL);
    if(pkt == NULL)
    {
        return NULL;
    }
    pkt->pktlen = pktlen;
    return &pkt->pkt;
}

int
udrv_send_user_pkt(struct udrv_dev *dev, struct udrv_pkt *pkt)
{
    int res;
    struct udrv_user_pkt *user_pkt =
        container_of(pkt, struct udrv_user_pkt, pkt);
    irq_lock_acquire(&dev->read_pkt_queue_lock);
    while(dev->read_pkts_queued > dev->max_read_pkts_queued)
    {
        int irq_flags;
        res =
            wait_on_irq_lock_release(&dev->send_wq, &dev->read_pkt_queue_lock, &irq_flags);
        if(res)
        {
            return res;
        }
        enable_restore_irqs(irq_flags);
        // We oculd be interrupted here...
        irq_lock_acquire(&dev->read_pkt_queue_lock);
    }
    ilist_push_head(&dev->read_pkt_queue, &user_pkt->queue_node);
    dev->read_pkts_queued++;

    udrv_dev_wake_readers(dev);

    irq_lock_release(&dev->read_pkt_queue_lock);

    return 0;
}

int
udrv_send_user_pkt_no_wait(struct udrv_dev *dev, struct udrv_pkt *pkt)
{
    struct udrv_user_pkt *user_pkt =
        container_of(pkt, struct udrv_user_pkt, pkt);

    irq_lock_acquire(&dev->read_pkt_queue_lock);
    ilist_push_head(&dev->read_pkt_queue, &user_pkt->queue_node);
    dev->read_pkts_queued++;

    udrv_dev_wake_readers(dev);

    irq_lock_release(&dev->read_pkt_queue_lock);

    return 0;
}

int
udrv_drop_user_pkt(struct udrv_dev *dev, struct udrv_pkt *pkt)
{
    struct udrv_user_pkt *user_pkt =
        container_of(pkt, struct udrv_user_pkt, pkt);
    kfree(user_pkt);
    return 0;
}

int
udrv_wake_driver(struct udrv_dev *dev)
{
    udrv_dev_wake_writers(dev);
    return 0;
}
