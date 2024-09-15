
#include <kanawha/fs/type.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/vmem.h>
#include <kanawha/stddef.h>
#include <kanawha/stdint.h>
#include <kanawha/assert.h>
#include <kanawha/vmem.h>
#include <kanawha/fs/cpio/cpio.h>
#include <kanawha/fs/cpio/mount.h>
#include <kanawha/fs/cpio/file.h>

#define CPIO_FS_TYPE_NAME "cpio"
#define CPIO_ROOT_INDEX 0x10000

static struct fs_mount_ops cpio_fs_mount_ops;

int
cpio_read_header(struct cpio_mount *mnt, size_t offset, struct cpio_header *hdr)
{
    int res;

    size_t size;

    switch(mnt->type) {
      case CPIO_BINARY:
        size = sizeof(struct cpio_binary_header);
        res = 0;
        break;
      case CPIO_ASCII:
        res = -EUNIMPL;
        break;
      default:
        res = -EINVAL;
        break;
    }

    if(res) {
        return res;
    }

    res = fs_node_paged_read(
        mnt->backing_file,
        offset,
        (void*)hdr,
        size);

    if(res) {
        eprintk("cpio_read_header: fs_node_paged_read -> %s (paged_read=%p)\n",
                errnostr(res),
                mnt->backing_file->node_ops->read_page);
        return res;
    }

    switch(mnt->type) {
        case CPIO_BINARY:
            if(hdr->binary.c_magic != CPIO_HEADER_MAGIC) {
                return -EINVAL;
            }
            break;
        default:
            break;
    }

    return 0;
}


static struct fs_node *
cpio_mount_load_node(
        struct fs_mount *fs_mnt,
        size_t node_index)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(fs_mnt));
    struct cpio_mount *mnt = container_of(fs_mnt, struct cpio_mount, fs_mount);

    if(node_index == CPIO_ROOT_INDEX) {
        return &mnt->root_node.fs_node;
    }

    struct cpio_header hdr;

    uintptr_t offset = 0;
    int found = 0;

    while(!found) {
        res = cpio_read_header(mnt, offset, &hdr);
        if(res) {
            return NULL;
        }

        if(hdr.binary.c_ino == node_index) {
            found = 1;
            break;
        }

        size_t namesize = hdr.binary.c_namesize;
        size_t filesize = hdr.binary.c_filesize[1] + ((size_t)hdr.binary.c_filesize[0]<<16);

        // Try and go to the next file
        offset += sizeof(struct cpio_binary_header);
        offset += (namesize + 1) & ~1;
        offset += (filesize + 1) & ~1;
    }

    if(!found) {
        return NULL;
    }

    struct cpio_file_node *node = kmalloc(sizeof(struct cpio_file_node));
    if(node == NULL) {
        return NULL;
    }
    memset(node, 0, sizeof(struct cpio_file_node));

    node->mnt = mnt;
    node->fs_node.file_ops = &cpio_file_ops;
    node->fs_node.node_ops = &cpio_node_ops;

    node->header_offset = offset;
    node->data_offset =
        node->header_offset
        + sizeof(struct cpio_binary_header)
        + ((hdr.binary.c_namesize + 1) & ~1);
    node->data_size = hdr.binary.c_filesize[1] + ((size_t)hdr.binary.c_filesize[0]<<16);

    return &node->fs_node;
}

static int
cpio_mount_unload_node(
        struct fs_mount *fs_mount,
        struct fs_node *fs_node)
{
    struct cpio_mount *mnt =
        container_of(fs_mount, struct cpio_mount, fs_mount);

    if(&mnt->root_node == container_of(fs_node, struct cpio_dir_node, fs_node)) {
        return 0;
    }

    struct cpio_file_node *node =
        container_of(fs_node, struct cpio_file_node, fs_node);

    kfree(node);

    return 0;
}

static int
cpio_mount_root_index(
        struct fs_mount *mnt,
        size_t *index)
{
    *index = CPIO_ROOT_INDEX;
    return 0;
}

int
cpio_mount_file(
        struct fs_type *fs_type,
        struct fs_node *backing_node,
        struct fs_mount **out_ptr)
{
    int res;
    struct cpio_mount *mnt = kmalloc(sizeof(struct cpio_mount));
    if(mnt == NULL) {
        return -ENOMEM;
    }
    memset(mnt, 0, sizeof(struct cpio_mount));

    res = init_fs_mount_struct(
            &mnt->fs_mount,
            &cpio_fs_mount_ops);
    if(res) {
        goto err0;
    }

    res = fs_node_get(backing_node);
    if(res) {
        goto err0;
    }

    mnt->backing_file = backing_node;

    mnt->type = CPIO_BINARY; // For now, this is all we will support

    mnt->root_node.mnt = mnt;
    mnt->root_node.fs_node.mount = &mnt->fs_mount;
    mnt->root_node.fs_node.node_ops = &cpio_dir_node_ops;
    mnt->root_node.fs_node.file_ops = &cpio_dir_file_ops;
    
    printk("Initialized CPIO Filesystem Mount\n");
    
    *out_ptr = &mnt->fs_mount;

    return 0;

err1:
    fs_node_put(mnt->backing_file);
err0:
    kfree(mnt);
    return res;
}

static int
cpio_unmount(
        struct fs_type *type,
        struct fs_mount *mnt)
{
    return -EUNIMPL;
}

static struct fs_mount_ops
cpio_fs_mount_ops = {
    .load_node = cpio_mount_load_node,
    .unload_node = cpio_mount_unload_node,
    .root_index = cpio_mount_root_index,
};

static struct fs_type
cpio_fs_type = {
    .mount_file = cpio_mount_file,
    .mount_special = fs_type_cannot_mount_special,
    .unmount = cpio_unmount,
};

static int
cpio_register(void) {
    return register_fs_type(&cpio_fs_type, CPIO_FS_TYPE_NAME);
}

declare_init_desc(fs, cpio_register, "Registering CPIO Archive Filesystem");

