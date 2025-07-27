
#include <kanawha/fs/file.h>
#include <kanawha/fs/node.h>
#include <kanawha/sysfs/sysfs.h>
#include <kanawha/sysfs/vfs.h>
#include <drivers/pci/match.h>
#include <drivers/pci/pci.h>
#include <drivers/pci/cfg.h>
#include <kanawha/stddef.h>
#include <kanawha/init.h>
#include <kanawha/string.h>

static struct vfs_mount *pci_fs_mount = NULL;
static struct fs_node_ops pci_fs_node_ops;
static struct fs_file_ops pci_fs_file_ops;

#define PCI_SYSFS_PAGE_ORDER (12)

static int
pci_cfg_fs_node_read_page(
        struct fs_node *fs_node,
        void *buffer,
        uintptr_t pfn,
        unsigned long flags)
{
    int res;

    struct vfs_node *vfs_node = fs_node->backing.priv_state;
    struct pci_func *func =
        container_of(vfs_node, struct pci_func, vfs_node);

    if(pfn != 0) {
        return -ENXIO;
    }

    memset(buffer, 0, (1ULL<<PCI_SYSFS_PAGE_ORDER));

    for(size_t offset = 0; offset < 0x100; offset += 4) {
        res = pci_func_readl(func, offset, buffer+offset);
        if(res) {
            return res;
        }
    }

    return 0;
}

static int
pci_cfg_fs_node_getattr(
        struct fs_node *fs_node,
        int attr,
        size_t *value)
{
    int res;

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            *value = 0x100;
            break;
        case FS_NODE_ATTR_PAGE_ORDER:
            *value = PCI_SYSFS_PAGE_ORDER;
            break;
        default:
            return -EINVAL;
    }
    return 0;
}

static struct fs_node_ops
pci_fs_node_ops =
{
    .read_page = pci_cfg_fs_node_read_page,
    .write_page = fs_node_cannot_write_page,
    .load_page = fs_node_load_page_read_alloc,
    .unload_page = fs_node_unload_page_free,
    .flush_page = fs_node_cannot_flush_page,
    .flush = fs_node_cannot_flush,
    .getattr = pci_cfg_fs_node_getattr,
    .setattr = fs_node_cannot_setattr,
    .lookup = fs_node_cannot_lookup,
    .mkfile = fs_node_cannot_mkfile,
    .mkdir = fs_node_cannot_mkdir,
    .link = fs_node_cannot_link,
    .symlink = fs_node_cannot_symlink,
    .unlink = fs_node_cannot_unlink,
};

static struct fs_file_ops
pci_fs_file_ops = {
    .read = fs_file_paged_read,
    .write = fs_file_eof_write,
    .flush = fs_file_nop_flush,
    .seek = fs_file_seek_pinned_zero,
    .poll = fs_file_cannot_poll,
    .dir_begin = fs_file_cannot_dir_begin,
    .dir_next = fs_file_cannot_dir_next,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
};

static int
insert_func_with_match_lock(
        struct pci_func *func)
{
    int res;

    func->vfs_node.fs_file_ops = &pci_fs_file_ops;
    func->vfs_node.fs_node_ops = &pci_fs_node_ops;

    char namebuf[32];
    snprintk(namebuf, 32, "%d.%d.%d.%d",
            func->device->segment->segment_id,
            func->device->bus->bus_index,
            func->device->index,
            func->index);
    namebuf[31] = '\0';

    size_t inode;
    res = vfs_mount_insert_node(
            pci_fs_mount,
            &func->vfs_node,
            &inode);
    if(res) {
        return res;
    }

    res = vfs_mount_link_root(
            pci_fs_mount,
            namebuf,
            inode);
    if(res) {
        return res;
    }

    return 0;
}

static int
pci_init_fs_mount(void)
{
    int res;

    struct vfs_mount *mnt;
    mnt = vfs_mount_create();
    if(mnt == NULL) {
        eprintk("Failed to create PCI VFS mount!\n");
        return -ENOMEM;
    }

    pci_fs_mount = mnt;

    spin_lock(&pci_match_lock);

    ilist_node_t *node;
    ilist_for_each(node, &pci_matched_func_list)
    {
        struct pci_func *func =
            container_of(node, struct pci_func, global_node);

        res = insert_func_with_match_lock(func);
        if(res) {
            spin_unlock(&pci_match_lock);
            return res;
        }
    }
    ilist_for_each(node, &pci_unmatched_func_list)
    {
        struct pci_func *func =
            container_of(node, struct pci_func, global_node);
        res = insert_func_with_match_lock(func);
        if(res) {
            spin_unlock(&pci_match_lock);
            return res;
        }
    }

    spin_unlock(&pci_match_lock);

    res = sysfs_register_mount(&pci_fs_mount->fs_mount, "pci");
    if(res) {
        return res;
    }

    return 0;
}

declare_init_desc(fs, pci_init_fs_mount, "Registering PCI Sysfs Mount");

int
pci_sysfs_on_register_pci_func(struct pci_func *func)
{
    if(pci_fs_mount == NULL) {
        return 0;
    }

    return insert_func_with_match_lock(func);
}

