
#include <kanawha/fs/file.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/flat.h>
#include <kanawha/fs/sys/sysfs.h>
#include <drivers/pci/match.h>
#include <drivers/pci/pci.h>
#include <kanawha/stddef.h>
#include <kanawha/init.h>

static struct flat_mount *pci_fs_mount = NULL;
static struct fs_node_ops pci_fs_node_ops;
static struct fs_file_ops pci_fs_file_ops;

static struct fs_node_ops
pci_fs_node_ops =
{
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_read_page,
    .flush = fs_node_cannot_flush,
    .getattr = fs_node_cannot_getattr,
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
    .read = fs_file_eof_read,
    .write = fs_file_eof_write,
    .flush = fs_file_nop_flush,
    .seek = fs_file_seek_pinned_zero,
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

    func->flat_node.fs_node.file_ops = &pci_fs_file_ops;
    func->flat_node.fs_node.node_ops = &pci_fs_node_ops;
    func->flat_node.fs_node.unload = NULL;

    char namebuf[32];
    snprintk(namebuf, 32, "%x:%x", func->vendor_id, func->device_id);
    namebuf[31] = '\0';
    res = flat_mount_insert_node(
            pci_fs_mount,
            &func->flat_node,
            namebuf);
    if(res) {
        return res;
    }

    return 0;
}

static int
pci_init_fs_mount(void)
{
    int res;

    struct flat_mount *mnt;
    mnt = flat_mount_create();
    if(mnt == NULL) {
        eprintk("Failed to create flat mount!\n");
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

