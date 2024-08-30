// Unix-Ware Boot File System (BFS) Driver

#include <kanawha/fs.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/vmem.h>

#define BFS_FS_TYPE_NAME "bfs"

#define BFS_BLOCK_ORDER 9
#define BFS_BLOCK_SIZE 512

struct bfs_blk_mount {
    struct fs_mount mnt;
    struct blk_dev *dev;
    size_t disk;

    size_t data_start_offset;
    size_t fs_size;
};

int
bfs_mount_blk_dev(
        struct fs_type *bfs,
        struct blk_dev *dev,
        size_t disk,
        struct fs_mount **out_ptr)
{
    int res;
    struct bfs_blk_mount *mnt = kmalloc(sizeof(struct bfs_blk_mount));
    if(mnt == NULL) {
        return -ENOMEM;
    }
    memset(mnt, 0, sizeof(struct bfs_blk_mount));

    res = init_fs_mount_struct(
            &mnt->mnt,
            bfs);
    if(res) {goto err0;}

    order_t order = blk_dev_sector_order(dev);
    if(order != BFS_BLOCK_ORDER) {
        // We'll be extra picky to keep this driver as simple as possible
        res = -EINVAL;
        goto err0;
    }

    struct cached_page *super_pg =
        blk_dev_get_sector(
                dev,
                disk,
                0);

    if(super_pg == NULL) {
        res = -EINVAL;
        goto err0;
    }

    res = cached_page_get(super_pg);
    if(res) {goto err1;}

    uint32_t *super_blk = (void*)__va(super_pg->cur_phys_addr);

    // If we're not the same endianness as BFS this will fail
    if(super_blk[0] != 0x1BADFACE) {
        if(super_blk[0] == 0xCEFABA01) {
            dprintk("Failed to mount BFS on block device, possibly an endianness problem!\n");
        }
        res = -EINVAL;
        goto err2;
    }

    // This has the right magic number
    mnt->data_start_offset = super_blk[1];
    mnt->fs_size = super_blk[2];

    cached_page_put(super_pg);
    blk_dev_put_sector(super_pg);

    // TODO
    
    *out_ptr = &mnt->mnt;
    return 0;

err2:
    cached_page_put(super_pg);
err1:
    blk_dev_put_sector(super_pg);
err0:
    kfree(mnt);
    return res;
}

static struct fs_type
bfs_fs_type = {
    .mount_blk_dev = bfs_mount_blk_dev,
};

static int
bfs_register(void) {
    return register_fs_type(&bfs_fs_type, BFS_FS_TYPE_NAME);
}

declare_init_desc(fs, bfs_register, "Registering Unix-Ware BFS Filesystem");

