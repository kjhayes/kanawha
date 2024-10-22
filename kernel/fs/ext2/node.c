
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/ext2/ext2.h>
#include <kanawha/fs/ext2/node.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>

static int
ext2_node_pfn_to_block(
        struct ext2_fs_node *node,
        uintptr_t pfn,
        size_t *block_no)
{
    int res;

    if(pfn < EXT2_INODE_DIRECT_BLOCKS) {
        *block_no = node->inode.block[pfn];
        return 0;
    }

    size_t entries_per_block = node->mount->block_size / sizeof(le32_t);

    size_t num_singly_indirect = entries_per_block + EXT2_INODE_DIRECT_BLOCKS;
    if(pfn < num_singly_indirect) {
        le32_t indirect_block = node->inode.block[EXT2_INODE_INDIRECT_BLOCK];
        le32_t entry;

        res = fs_node_paged_read(
                node->mount->backing_node,
                EXT2_BLOCK_OFFSET(indirect_block, node->mount->block_size)
                    + (sizeof(le32_t) * (pfn-EXT2_INODE_DIRECT_BLOCKS)),
                &entry,
                sizeof(le32_t),
                0);
        if(res) {
            return res;
        }

        *block_no = entry;
        return 0;
    }

    // TODO Doubly and Triply Indirect Blocks

    return -EINVAL;
}

static int
ext2_node_set_pfn_block(
        struct ext2_fs_node *node,
        uintptr_t pfn,
        size_t block_no)
{
    int res;

    if(pfn < EXT2_INODE_DIRECT_BLOCKS) {
        node->inode.block[pfn] = block_no;
        node->inode_dirty = 1;
        return 0;
    }

    // TODO Singly, Doubly and Triply Indirect Blocks

    return -EINVAL;
}

size_t
ext2_fs_node_to_group_num(
        struct ext2_fs_node *node)
{
    struct ext2_mount *mnt = node->mount;
    size_t inode_index = node->fs_node.cache_node.key;

    return (inode_index-1) / mnt->inodes_per_group;
}

int
ext2_fs_node_read_page(
        struct fs_node *fs_node,
        void *page,
        uintptr_t pfn,
        unsigned long flags)
{
    int res;

    struct ext2_fs_node *node =
        container_of(fs_node, struct ext2_fs_node, fs_node);

    size_t block_no;
    res = ext2_node_pfn_to_block(node, pfn, &block_no);
    if(res) {
        return res;
    }

    if(block_no == 0 && (flags & FS_NODE_READ_PAGE_MAY_CREATE)) {
        memset(page, 0, node->mount->block_size);
        return 0;
    } else {
        res = fs_node_paged_read(
                node->mount->backing_node,
                EXT2_BLOCK_OFFSET(block_no, node->mount->block_size),
                page,
                node->mount->block_size,
                0);
        if(res) {
            return res;
        }
        return 0;
    }
}

int
ext2_fs_node_write_page(
        struct fs_node *fs_node,
        void *page,
        uintptr_t pfn,
        unsigned long flags)
{
    int res;

    dprintk("ext2_fs_node_write_page pfn=%p\n", pfn);

    struct ext2_fs_node *node =
        container_of(fs_node, struct ext2_fs_node, fs_node);

    size_t block_no;
    res = ext2_node_pfn_to_block(node, pfn, &block_no);
    if(res) {
        eprintk("ext2_fs_node_write_page: Failed to get block_no of pfn=%p! (err=%s)\n",
                pfn, errnostr(res));
        return res;
    }

    if(block_no == 0 && (flags & FS_NODE_WRITE_PAGE_MAY_CREATE)) {
        res = ext2_mount_alloc_block(
                node->mount,
                ext2_fs_node_to_group_num(node),
                &block_no);
        if(res) {
            eprintk("ext2_fs_node_write_page: failed to allocate block (err=%s)\n",
                    errnostr(res));
            return res;
        }
        res = ext2_node_set_pfn_block(node, pfn, block_no);
        if(res) {
            eprintk("ext2_fs_node_write_page: failed to set block in inode (err=%s)\n",
                    errnostr(res));
            return res;
        }

        dprintk("Allocated new block(0x%llx) for ext2_fs_node(%p)\n",
                (ull_t)block_no,
                node);
    }

    res = fs_node_paged_write(
            node->mount->backing_node,
            EXT2_BLOCK_OFFSET(block_no, node->mount->block_size),
            page,
            node->mount->block_size,
            0);
    if(res) {
        eprintk("ext2_fs_node_write_page: failed to write to backing fs_node (err=%s)\n",
            errnostr(res));
        return res;
    }
    return 0;
}

int
ext2_fs_node_getattr(
        struct fs_node *fs_node,
        int attr,
        size_t *value)
{
    struct ext2_fs_node *node =
        container_of(fs_node, struct ext2_fs_node, fs_node);

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            *value = ((size_t)node->inode.size) | (((size_t)node->inode.dir_acl)<<32);
            break;
        case FS_NODE_ATTR_PAGE_ORDER:
            *value = node->mount->block_order;
            break;
        default:
            return -EINVAL;
    }

    return 0;
}

int
ext2_fs_node_setattr(
        struct fs_node *fs_node,
        int attr,
        size_t value)
{
    struct ext2_fs_node *node =
        container_of(fs_node, struct ext2_fs_node, fs_node);

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            node->inode.size = value & 0xFFFFFFFF;
            node->inode.dir_acl = (uint64_t)value >> 32;
            node->inode_dirty = 1;
            return 0;
    }

    return -EINVAL;
}

int
ext2_fs_node_flush(
        struct fs_node *fs_node)
{
    struct ext2_fs_node *node =
        container_of(fs_node, struct ext2_fs_node, fs_node);

    return -EUNIMPL;
}

