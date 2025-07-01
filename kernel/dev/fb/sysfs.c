
#include <kanawha/dev/fb.h>

#include <kanawha/page_alloc.h>
#include <kanawha/vmem.h>
#include <kanawha/lock.h>
#include <kanawha/spinlock.h>
#include <kanawha/stree.h>
#include <kanawha/init.h>
#include <kanawha/string.h>
#include <kanawha/parse.h>
#include <kanawha/kmalloc.h>

#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/sys/vfs.h>
#include <kanawha/fs/sys/sysfs.h>

#include <kanawha/uapi/file.h>

struct fb_dev_fs_node
{
    struct fb_dev *dev;

    spinlock_t buffer_lock;
    size_t buffer_mode;
    struct fb_mode_info *buffer_info;
    size_t buffer_pages_loaded;
    void __phys *buffer_addr;
    void __phys *buffer_tail_page;
    ssize_t buffer_tail_pfn;

    struct vfs_node buffer_vfs_node;
    struct vfs_node mode_set_vfs_node;
    struct vfs_node mode_info_vfs_node;
    size_t mode_info_vfs_current_mode;
};

static struct vfs_mount *fb_dev_fs_mount = NULL;
static struct fb_dev_registry_hook *fb_dev_fs_hook = NULL;

static int
fb_dev_buffer_fs_node_load_page(
        struct fs_node *fs_node,
        uintptr_t pfn,
        unsigned long flags,
        void __phys ** addr_out)
{
    int res;
    struct fb_dev_fs_node *fbfs =
        container_of(fs_node, struct fb_dev_fs_node, buffer_vfs_node.fs_node);

    DEBUG_ASSERT(KERNEL_ADDR(fbfs));
    DEBUG_ASSERT(KERNEL_ADDR(fbfs->dev));

    spin_lock(&fbfs->buffer_lock);
    if(fbfs->buffer_pages_loaded == 0)
    {
        fbfs->buffer_mode = fb_dev_get_mode(fbfs->dev);
        if(fbfs->buffer_mode < 0) {
            spin_unlock(&fbfs->buffer_lock);
            return fbfs->buffer_mode;
        }
        fbfs->buffer_info = fb_dev_get_mode_info(fbfs->dev, fbfs->buffer_mode);
        if(fbfs->buffer_info == NULL) {
            spin_unlock(&fbfs->buffer_lock);
            return res;
        }

        if(fbfs->buffer_info->buffer_size & ((1ULL<<VMEM_MIN_PAGE_ORDER)-1)) {
            res = page_alloc(
                    VMEM_MIN_PAGE_ORDER,
                    &fbfs->buffer_tail_page,
                    0);
            if(res) {
                fb_dev_put_mode_info(fbfs->dev, fbfs->buffer_mode); 
                spin_unlock(&fbfs->buffer_lock);
                return res;
            }
            fbfs->buffer_tail_pfn = (fbfs->buffer_info->buffer_size>>VMEM_MIN_PAGE_ORDER);
        } else {
            fbfs->buffer_tail_pfn = -1; // No tail page
        }

        res = fb_dev_load_buffer(
                fbfs->dev,
                &fbfs->buffer_addr);
        if(res) {
            fb_dev_put_mode_info(fbfs->dev, fbfs->buffer_mode); 
            spin_unlock(&fbfs->buffer_lock);
            return res;
        }

        // Copy over the tail page in-case we have been opened for reading
        if(fbfs->buffer_tail_pfn >= 0) {
            void *tail_page = __va(fbfs->buffer_tail_page);
            void *buffer = __va(fbfs->buffer_addr);

            size_t tail_page_offset = fbfs->buffer_tail_pfn<<VMEM_MIN_PAGE_ORDER;
            DEBUG_ASSERT(tail_page_offset < fbfs->buffer_info->buffer_size);
            size_t tail_page_data_size = fbfs->buffer_info->buffer_size - tail_page_offset;

            memcpy(tail_page, buffer + tail_page_offset, tail_page_data_size);
        }
        
        // TODO (We could support this by allowing a "head" page similar to the "tail" page to
        // catch "non-page size multiple" layer data cases
        DEBUG_ASSERT_MSG(((uintptr_t)fbfs->buffer_addr & ((1ULL<<VMEM_MIN_PAGE_ORDER)-1)) == 0,
                "Framebuffer Device Returned Layer Data Which is Not Page Aligned!");
    }
    fbfs->buffer_pages_loaded++;
    spin_unlock(&fbfs->buffer_lock);

    size_t page_offset = (pfn<<VMEM_MIN_PAGE_ORDER);

    if(page_offset >= fbfs->buffer_info->buffer_size) {
        // This page is out of range of the layer data
        return -EINVAL;
    }

    if(pfn == fbfs->buffer_tail_pfn) {
        *addr_out = fbfs->buffer_tail_page;
    } else {
        *addr_out = fbfs->buffer_addr + page_offset;
    }

    return 0;
}

static int
fb_dev_buffer_fs_node_unload_page(
        struct fs_node *fs_node,
        uintptr_t pfn,
        unsigned long flags,
        void __phys *addr)
{
    int res;
    struct fb_dev_fs_node *fbfs =
        container_of(fs_node, struct fb_dev_fs_node, buffer_vfs_node.fs_node);

    DEBUG_ASSERT(KERNEL_ADDR(fbfs));
    DEBUG_ASSERT(KERNEL_ADDR(fbfs->dev));

    spin_lock(&fbfs->buffer_lock);
    fbfs->buffer_pages_loaded--;
    if(fbfs->buffer_pages_loaded == 0) {
        res = fb_dev_unload_buffer(
                fbfs->dev,
                fbfs->buffer_addr);
        if(res) {
            fbfs->buffer_pages_loaded++;
            spin_unlock(&fbfs->buffer_lock);
            return res;
        }
        if(fbfs->buffer_tail_pfn >= 0) {
            res = page_free(VMEM_MIN_PAGE_ORDER, fbfs->buffer_tail_page);
            if(res) {
                wprintk("Failed to free framebuffer tail page! (Leaking memory) (err=%s)\n",
                        errnostr(res));
            }
            fbfs->buffer_tail_pfn = -1;
        }

        fbfs->buffer_info = NULL;
        res = fb_dev_put_mode_info(fbfs->dev, fbfs->buffer_mode);
    }
    spin_unlock(&fbfs->buffer_lock);

    return 0;
}

static int
fb_dev_buffer_fs_node_flush_page(
        struct fs_node *fs_node,
        uintptr_t pfn,
        unsigned long flags,
        void __phys *addr)
{
    int res;
    struct fb_dev_fs_node *fbfs =
        container_of(fs_node, struct fb_dev_fs_node, buffer_vfs_node.fs_node);
    DEBUG_ASSERT(KERNEL_ADDR(fbfs));
    DEBUG_ASSERT(KERNEL_ADDR(fbfs->dev));

    spin_lock(&fbfs->buffer_lock);

    if(pfn == fbfs->buffer_tail_pfn) {
        void *tail_page = __va(fbfs->buffer_tail_page);
        void *buffer = __va(fbfs->buffer_addr);

        size_t tail_page_offset = fbfs->buffer_tail_pfn<<VMEM_MIN_PAGE_ORDER;
        DEBUG_ASSERT(tail_page_offset < fbfs->buffer_info->buffer_size);
        size_t tail_page_data_size = fbfs->buffer_info->buffer_size - tail_page_offset;

        DEBUG_ASSERT_MSG(tail_page_data_size < 1ULL<<VMEM_MIN_PAGE_ORDER,
                "Framebuffer tail page is larger than VMEM_MIN_PAGE_ORDER (not strictly a problem but unexpected)");

        memcpy(buffer + tail_page_offset, tail_page, tail_page_data_size);
    }

    spin_unlock(&fbfs->buffer_lock);

    // TODO This is ridiculuously inefficient (flushing full buffer on every page flush)
//    res = fb_dev_flush_buffer(dev);
//    if(res) {
//        return res;
//    }

    return 0;
}

static int
fb_dev_buffer_fs_node_getattr(
        struct fs_node *fs_node,
        int attr,
        size_t *value)
{
    int res;
    struct fb_dev_fs_node *fbfs =
        container_of(fs_node, struct fb_dev_fs_node, buffer_vfs_node.fs_node);
    DEBUG_ASSERT(KERNEL_ADDR(fbfs));
    DEBUG_ASSERT(KERNEL_ADDR(fbfs->dev));

    spin_lock(&fbfs->buffer_lock);

    size_t mode;
    struct fb_mode_info *info;
    if(fbfs->buffer_pages_loaded > 0) {
        mode = fbfs->buffer_mode;
        info = fbfs->buffer_info;
    } else {
        mode = fb_dev_get_mode(fbfs->dev);
        info = fb_dev_get_mode_info(fbfs->dev, mode);
    }

    if(info == NULL) {
        spin_unlock(&fbfs->buffer_lock);
        return -EINVAL;
    }

    res = 0; // Default to zero (success)
    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            *value = info->buffer_size;
            break;
        case FS_NODE_ATTR_PAGE_ORDER:
            *value = VMEM_MIN_PAGE_ORDER;
            break;
        default:
            res = -ENXIO;
            break;
    }

exit:
    if(fbfs->buffer_pages_loaded == 0) {
        fb_dev_put_mode_info(fbfs->dev, mode);
    }
    spin_unlock(&fbfs->buffer_lock);

    return res;
}

static int
fb_dev_buffer_fs_file_flush(
        struct file *file,
        unsigned long flags)
{
    int res;

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -ENXIO;
    }
    struct fb_dev_fs_node *fbfs =
        container_of(fs_node, struct fb_dev_fs_node, buffer_vfs_node.fs_node);
    DEBUG_ASSERT(KERNEL_ADDR(fbfs));
    DEBUG_ASSERT(KERNEL_ADDR(fbfs->dev));

    if(fbfs->buffer_tail_pfn >= 0) {
        fs_node_flush_all_fs_pages(fs_node);
    }

    res = fb_dev_flush_buffer(fbfs->dev);
    if(res) {
        return res;
    }

    return 0;
}

static struct fs_node_ops fb_dev_buffer_fs_node_ops = {
    .lookup = vfs_dir_lookup,

    .load_page = fb_dev_buffer_fs_node_load_page,
    .unload_page = fb_dev_buffer_fs_node_unload_page,
    .flush_page = fb_dev_buffer_fs_node_flush_page,

    .flush = fs_node_flush_nop,
    .getattr = fb_dev_buffer_fs_node_getattr,
    .setattr = fs_node_cannot_setattr,
 
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_write_page,
 
    .link = fs_node_cannot_link,
    .unlink = fs_node_cannot_unlink,
    .mkdir = fs_node_cannot_mkdir,
    .mkfifo = fs_node_cannot_mkfifo,
    .mkfile = fs_node_cannot_mkfile,
    .symlink = fs_node_cannot_symlink,
};
static struct fs_file_ops fb_dev_buffer_fs_file_ops =
{
    .dir_begin = vfs_dir_begin,
    .dir_next = vfs_dir_next,
    .dir_readattr = vfs_dir_readattr,
    .dir_readname = vfs_dir_readname,

    .read = fs_file_paged_read,
    .write = fs_file_paged_write,
    .flush = fb_dev_buffer_fs_file_flush,
    .seek = fs_file_paged_seek,
    .poll = fs_file_cannot_poll,
};

static ssize_t
fb_dev_mode_set_fs_file_write(
        struct file *file,
        void *buf,
        ssize_t buflen,
        unsigned long flags)
{
    int res;

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -ENXIO;
    }
    struct fb_dev_fs_node *fbfs =
        container_of(fs_node, struct fb_dev_fs_node, mode_set_vfs_node.fs_node);
    DEBUG_ASSERT(KERNEL_ADDR(fbfs));
    DEBUG_ASSERT(KERNEL_ADDR(fbfs->dev));

    if(file->seek_offset != 0) {
        return 0;
    }

    char str_buf[buflen+1];
    memcpy(str_buf, buf, buflen);
    str_buf[buflen] = '\0';

    unsigned long long value = parse_unsigned_long_long(str_buf, 0);

    spin_lock(&fbfs->buffer_lock);

    if(fbfs->buffer_pages_loaded > 0) {
        if(fb_dev_get_mode(fbfs->dev) != value) {
            // Cannot change modes while the buffer is loaded
            spin_unlock(&fbfs->buffer_lock);
            return -EBUSY;
        }
    }
    res = fb_dev_set_mode(fbfs->dev, value);
    if(res) {
        spin_unlock(&fbfs->buffer_lock);
        return res;
    }

    spin_unlock(&fbfs->buffer_lock);

    return buflen;
}

static ssize_t
fb_dev_mode_set_fs_file_read(
        struct file *file,
        void *buf,
        ssize_t buflen,
        unsigned long flags)
{
    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -ENXIO;
    }
    struct fb_dev_fs_node *fbfs =
        container_of(fs_node, struct fb_dev_fs_node, mode_set_vfs_node.fs_node);
    DEBUG_ASSERT(KERNEL_ADDR(fbfs));
    DEBUG_ASSERT(KERNEL_ADDR(fbfs->dev));

    if(file->seek_offset != 0) {
        return 0;
    }

    ssize_t index = fb_dev_get_mode(fbfs->dev);
    if(index < 0) {
        return index;
    }

    int attempted = snprintk(buf, buflen, "%lld\n", (sll_t)index);

    return attempted < buflen ? attempted : buflen;
}

static int
fb_dev_mode_set_fs_node_setattr(
        struct fs_node *node,
        int attr,
        size_t value)
{
    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            if(value == 0) {
                // Ignore it
                return 0;
            } else {
                return -EINVAL;
            }
        default:
            return -EINVAL;
    }
}

static struct fs_node_ops fb_dev_mode_set_fs_node_ops =
{
    .setattr = fb_dev_mode_set_fs_node_setattr,

    .flush = fs_node_flush_nop,

    .lookup = fs_node_cannot_lookup, 
    .link = fs_node_cannot_link,
    .unlink = fs_node_cannot_unlink,
    .mkdir = fs_node_cannot_mkdir,
    .mkfifo = fs_node_cannot_mkfifo,
    .mkfile = fs_node_cannot_mkfile,
    .getattr = fs_node_cannot_getattr,
    .symlink = fs_node_cannot_symlink,
    .load_page = fs_node_cannot_load_page,
    .unload_page = fs_node_cannot_unload_page,
    .flush_page = fs_node_cannot_flush_page,
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_write_page,
};
static struct fs_file_ops fb_dev_mode_set_fs_file_ops =
{
    .read = fb_dev_mode_set_fs_file_read,
    .write = fb_dev_mode_set_fs_file_write,
    .seek = fs_file_seek_pinned_zero,

    .dir_begin = fs_file_cannot_dir_begin,
    .dir_next = fs_file_cannot_dir_next,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
    .flush = fs_file_cannot_flush,
    .poll = fs_file_cannot_poll,
};

static int
fb_dev_mode_info_fs_node_setattr(
        struct fs_node *node,
        int attr,
        size_t value)
{
    struct fb_dev_fs_node *fbfs =
        container_of(node, struct fb_dev_fs_node, mode_info_vfs_node.fs_node);
    DEBUG_ASSERT(KERNEL_ADDR(fbfs));
    DEBUG_ASSERT(KERNEL_ADDR(fbfs->dev));

    switch(attr)
    {
        case FS_NODE_ATTR_DATA_SIZE:
            if(value == 0) {
                // Ignore it
                return 0;
            } else {
                return -EINVAL;
            }
        default:
            return -EINVAL;
    }
}

static int
fb_dev_mode_info_fs_node_getattr(
        struct fs_node *node,
        int attr,
        size_t *value)
{
    int res;

    struct fb_dev_fs_node *fbfs =
        container_of(node, struct fb_dev_fs_node, mode_info_vfs_node.fs_node);
    DEBUG_ASSERT(KERNEL_ADDR(fbfs));
    DEBUG_ASSERT(KERNEL_ADDR(fbfs->dev));

    struct fb_mode_info *info =
        fb_dev_get_mode_info(fbfs->dev, fbfs->mode_info_vfs_current_mode);

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            if(info == NULL) {
                *value = 0;
            } else {
                *value = sizeof(struct fb_mode_info) + (sizeof(struct fb_layer_info) * info->layer_count);
            }
            return 0;
        default:
            return -EINVAL;
    }
}

static ssize_t
fb_dev_mode_info_fs_file_write(
        struct file *file,
        void *buf,
        ssize_t buflen,
        unsigned long flags)
{
    int res;

    struct fs_node *node = fs_path_get_fs_node(file->path);
    if(node == NULL) {
        return -ENXIO;
    }

    struct fb_dev_fs_node *fbfs =
        container_of(node, struct fb_dev_fs_node, mode_info_vfs_node.fs_node);
    DEBUG_ASSERT(KERNEL_ADDR(fbfs));
    DEBUG_ASSERT(KERNEL_ADDR(fbfs->dev));

    if(file->seek_offset != 0) {
        return 0;
    }

    char str_buf[buflen+1];
    memcpy(str_buf, buf, buflen);
    str_buf[buflen] = '\0';

    unsigned long long value = parse_unsigned_long_long(str_buf, 0);
    fbfs->mode_info_vfs_current_mode = value;

    return buflen;
}

static ssize_t
fb_dev_mode_info_fs_file_read(
        struct file *file,
        void *buf,
        ssize_t buflen,
        unsigned long flags)
{
    DEBUG_ASSERT(KERNEL_ADDR(file));
    DEBUG_ASSERT(KERNEL_ADDR(file->path));

    struct fs_node *node = fs_path_get_fs_node(file->path);
    if(node == NULL) {
        return -ENXIO;
    }
    struct fb_dev_fs_node *fbfs =
        container_of(node, struct fb_dev_fs_node, mode_info_vfs_node.fs_node);

    DEBUG_ASSERT(KERNEL_ADDR(fbfs));
    DEBUG_ASSERT(KERNEL_ADDR(fbfs->dev));

    struct fb_mode_info *info =
        fb_dev_get_mode_info(fbfs->dev, fbfs->mode_info_vfs_current_mode);
    if(info == NULL) {
        if(file->seek_offset == 0) {
            return 0; // Nothing to read
        } else {
            return -EINVAL;
        }
    } 

    size_t size = sizeof(struct fb_mode_info) + (sizeof(struct fb_layer_info) * info->layer_count);
    if(file->seek_offset > size) {
        return -EINVAL;
    }

    size_t room_left = size - file->seek_offset;
    if(room_left > buflen) {
        room_left = buflen;
    }

    memcpy(buf, info, room_left);

    return room_left;
}


static struct fs_node_ops fb_dev_mode_info_fs_node_ops =
{
    .setattr = fb_dev_mode_info_fs_node_setattr,
    .getattr = fb_dev_mode_info_fs_node_getattr,

    .flush = fs_node_flush_nop,

    .lookup = fs_node_cannot_lookup, 
    .link = fs_node_cannot_link,
    .unlink = fs_node_cannot_unlink,
    .mkdir = fs_node_cannot_mkdir,
    .mkfifo = fs_node_cannot_mkfifo,
    .mkfile = fs_node_cannot_mkfile,
    .symlink = fs_node_cannot_symlink,
    .load_page = fs_node_cannot_load_page,
    .unload_page = fs_node_cannot_unload_page,
    .flush_page = fs_node_cannot_flush_page,
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_write_page,
};
static struct fs_file_ops fb_dev_mode_info_fs_file_ops =
{
    .read = fb_dev_mode_info_fs_file_read,
    .write = fb_dev_mode_info_fs_file_write,
    .seek = fs_file_paged_seek,
    .flush = fs_file_cannot_flush,
    .poll = fs_file_cannot_poll,

    .dir_begin = fs_file_cannot_dir_begin,
    .dir_next = fs_file_cannot_dir_next,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
};

static void
fb_dev_fs_on_register(
        struct fb_dev *dev)
{
    int res;

    struct fb_dev_fs_node *fbfs = kmalloc(sizeof(*fbfs));
    if(fbfs == NULL) {
        return;
    }
    memset(fbfs, 0, sizeof(*fbfs));

    fbfs->dev = dev;

    spinlock_init(&fbfs->buffer_lock);
    fbfs->buffer_pages_loaded = 0;
    fbfs->mode_info_vfs_current_mode = 0;

    size_t buffer_inode;

    fbfs->buffer_vfs_node.fs_node.unload = NULL;
    fbfs->buffer_vfs_node.fs_node.node_ops = &fb_dev_buffer_fs_node_ops;
    fbfs->buffer_vfs_node.fs_node.file_ops = &fb_dev_buffer_fs_file_ops;

    res = vfs_mount_insert_node_and_link_root(
            fb_dev_fs_mount,
            &fbfs->buffer_vfs_node,
            fb_dev_get_name(dev));
    if(res) {
        dprintk("vfs_mount_insert_node_and_link_root returned %s\n",
                errnostr(res));
        goto err0;
    }

    size_t mode_set_inode;

    fbfs->mode_set_vfs_node.fs_node.unload = NULL;
    fbfs->mode_set_vfs_node.fs_node.node_ops = &fb_dev_mode_set_fs_node_ops;
    fbfs->mode_set_vfs_node.fs_node.file_ops = &fb_dev_mode_set_fs_file_ops;

    res = vfs_mount_insert_node(
            fb_dev_fs_mount,
            &fbfs->mode_set_vfs_node,
            &mode_set_inode);
    if(res) {
        goto err2;
    }

    res = vfs_node_link(
            &fbfs->buffer_vfs_node,
            "mode",
            mode_set_inode);
    if(res) {
        goto err3;
    }

    size_t mode_info_inode;

    fbfs->mode_info_vfs_node.fs_node.unload = NULL;
    fbfs->mode_info_vfs_node.fs_node.node_ops = &fb_dev_mode_info_fs_node_ops;
    fbfs->mode_info_vfs_node.fs_node.file_ops = &fb_dev_mode_info_fs_file_ops;

    res = vfs_mount_insert_node(
            fb_dev_fs_mount,
            &fbfs->mode_info_vfs_node,
            &mode_info_inode);
    if(res) {
        goto err3;
    }

    res = vfs_node_link(
            &fbfs->buffer_vfs_node,
            "info",
            mode_info_inode);
    if(res) {
        goto err4;
    }

    return;

err4:
    vfs_mount_remove_node(
        fb_dev_fs_mount,
        &fbfs->mode_info_vfs_node);
err3:
    vfs_mount_remove_node(
        fb_dev_fs_mount,
        &fbfs->mode_set_vfs_node);
err2:
    vfs_mount_unlink_root(
        fb_dev_fs_mount,
        fb_dev_get_name(dev));
    vfs_node_unlink_all(&fbfs->buffer_vfs_node);
err1:
    vfs_mount_remove_node(
        fb_dev_fs_mount,
        &fbfs->buffer_vfs_node);
err0:
    return;
}

static void
fb_dev_fs_on_unregister(
        struct fb_dev *dev)
{
    panic("Tried to unregister fb_dev from sysfs! (UNIMPL)\n");
}

static int
fb_dev_init_fs_mount(void)
{
    int res;
    struct vfs_mount *mnt;
    mnt = vfs_mount_create();
    if(mnt == NULL) {
        eprintk("Failed to create VFS mount for sysfs framebuffers!\n");
        return -ENOMEM;
    }

    fb_dev_fs_mount = mnt;

    struct fb_dev_registry_hook *hook;
    hook = hook_fb_dev_registry(
            fb_dev_fs_on_register,
            fb_dev_fs_on_unregister);
    if(hook == NULL) {
        vfs_mount_destroy(mnt);
        return -ENOMEM;
    }

    fb_dev_fs_hook = hook;

    res = sysfs_register_mount(
            &fb_dev_fs_mount->fs_mount,
            "fbdev");
    if(res) {
        fb_dev_fs_hook = NULL;
        unhook_fb_dev_registry(hook);
        fb_dev_fs_mount = NULL;
        vfs_mount_destroy(mnt);
        return res;
    }

    return 0;
}

declare_init_desc(fs, fb_dev_init_fs_mount, "Registering fbdev Sysfs Mount");
