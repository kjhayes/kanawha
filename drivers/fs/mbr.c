
#include <kanawha/fs/type.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/vmem.h>
#include <kanawha/stddef.h>
#include <kanawha/types.h>
#include <kanawha/assert.h>
#include <kanawha/vmem.h>
#include <kanawha/parse.h>
#include <kanawha/endian.h>

#define MBR_PARTITION_ENTRY_OFFSET (0x1BE)
#define MBR_BOOT_SIGNATURE_OFFSET  (0x1FE)

#define MBR_BOOT_SIGNATURE (htole16(0xAA55))

struct __packed mbr_partition_entry {
    uint8_t status;
    uint8_t chs_first[3];
    uint8_t type;
    uint8_t chs_last[3];
    le32_t lba_base;
    le32_t lba_count;
};

ASSERT_TYPE_SIZE(struct mbr_partition_entry, 16);

struct mbr_mount {
    struct fs_mount fs_mount;
    struct fs_node *backing_node;

    order_t sector_order;
    order_t page_order;
};

struct mbr_partition
{
    struct fs_node *fs_node;

    size_t sector_offset;
    size_t num_sectors;
};

static struct fs_mount_ops mbr_fs_mount_ops;

static struct fs_node_ops mbr_root_dir_node_ops;
static struct fs_file_ops mbr_root_dir_file_ops;

static struct fs_node_ops mbr_unaligned_partition_node_ops;
static struct fs_file_ops mbr_unaligned_partition_file_ops;

static struct fs_node_ops mbr_aligned_partition_node_ops;
static struct fs_file_ops mbr_aligned_partition_file_ops;

static int
mbr_mount_load_partition_entry(
	struct mbr_mount *mnt,
	size_t index,
	struct mbr_partition_entry *entry)
{
    int res;

    size_t offset = 0;

    if(index > 0 && index <= 4) {
	offset = MBR_PARTITION_ENTRY_OFFSET + (sizeof(struct mbr_partition_entry) * (index-1));
    } else {
	return -ENXIO;
    }

    res = fs_node_paged_read(
	    mnt->backing_node,
	    offset,
	    entry,
	    sizeof(*entry),
	    0);
    if(res) {
	return res;
    }

    if(entry->type == 0x0) {
	return -ENXIO;
    }

    return 0;
}

static int
mbr_mount_load_node(
        struct fs_mount *fs_mount,
        size_t node_index,
	struct fs_node *fs_node)
{
    int res;

    struct mbr_mount *mnt =
	container_of(fs_mount, struct mbr_mount, fs_mount);

    if(node_index < 0) {
	return -EINVAL;
    }

    if(node_index == 0) {
	// The Root Directory
	fs_node->backing.node_ops = &mbr_root_dir_node_ops;
	fs_node->backing.file_ops = &mbr_root_dir_file_ops;
	fs_node->backing.priv_state = mnt;
        return 0;
    }

    struct mbr_partition_entry entry;
    res = mbr_mount_load_partition_entry(mnt, node_index, &entry);
    if(res) {
	return res;
    }

    struct mbr_partition *part = kzmalloc(sizeof(*part), KM_KERNEL);
    if(part == NULL) {
        return -ENOMEM;
    }
    part->fs_node = fs_node;

    part->sector_offset = letoh32(entry.lba_base);
    part->num_sectors = letoh32(entry.lba_count);
    
    size_t offset = part->sector_offset << mnt->sector_order;
    size_t size = part->num_sectors << mnt->sector_order;

    size_t align_mask = (1ULL<<mnt->page_order)-1;

    if((offset & align_mask) == 0 && (size & align_mask) == 0) {
        fs_node->backing.node_ops = &mbr_aligned_partition_node_ops;
        fs_node->backing.file_ops = &mbr_aligned_partition_file_ops;
    } else {
        fs_node->backing.node_ops = &mbr_unaligned_partition_node_ops;
        fs_node->backing.file_ops = &mbr_unaligned_partition_file_ops;
    }

    fs_node->backing.priv_state = part;
    return 0;
}

static int
mbr_mount_unload_node(
        struct fs_mount *fs_mount,
	size_t index,
        struct fs_node *fs_node)
{
    int res;
    if(index > 0) {
	struct mbr_partition *part = fs_node->backing.priv_state;
	kfree(part);
    }
    return 0;
}

static int
mbr_mount_root_index(
        struct fs_mount *mnt,
        size_t *index)
{
    int res;
    *index = 0;
    return 0;
}

static int
mbr_mount_sync(
        struct fs_mount *fs_mount)
{
    int res;

    struct mbr_mount *mnt = container_of(fs_mount, struct mbr_mount, fs_mount);

    res = fs_node_flush_all_fs_pages(mnt->backing_node);
    if(res) {
        return res;
    }

    return 0;
}

int
mbr_mount_file(
        struct fs_type *fs_type,
        struct fs_node *backing_node,
        struct fs_mount **out_ptr)
{
    int res;
    struct mbr_mount *mnt = kzmalloc(sizeof(struct mbr_mount), KM_KERNEL);
    if(mnt == NULL) {
        return -ENOMEM;
    }

    res = init_fs_mount_struct(
            &mnt->fs_mount,
            &mbr_fs_mount_ops);
    if(res) {
        goto err0;
    }

    res = fs_node_get(backing_node);
    if(res) {
        goto err0;
    }

    mnt->backing_node  = backing_node;

    {
        size_t order;
        res = fs_node_getattr(backing_node, FS_NODE_ATTR_SECTOR_ORDER, &order);
        if(res) {
            goto err1;
        }
        mnt->sector_order = order;
   
        res = fs_node_getattr(backing_node, FS_NODE_ATTR_PAGE_ORDER, &order);
        if(res) {
            goto err1;
        }
        mnt->page_order = order;
    }

    *out_ptr = &mnt->fs_mount;
   
    return 0;

err1:
    fs_node_put(mnt->backing_node);
err0:
    kfree(mnt);
    return res;
}

static int
mbr_unmount(
        struct fs_type *type,
        struct fs_mount *fs_mount)
{
    struct mbr_mount *mnt = container_of(fs_mount, struct mbr_mount, fs_mount);
    fs_node_put(mnt->backing_node);
    kfree(mnt);
    return 0;
}

static struct fs_mount_ops
mbr_fs_mount_ops = {
    .load_node = mbr_mount_load_node,
    .unload_node = mbr_mount_unload_node,
    .root_index = mbr_mount_root_index,
    .sync = mbr_mount_sync,
};

static struct fs_type
mbr_fs_type = {
    .mount_file = mbr_mount_file,
    .mount_special = fs_type_cannot_mount_special,
    .unmount = mbr_unmount,
};

static int
mbr_root_dir_getattr(
        struct fs_node *fs_node,
        int attr,
        size_t *value)
{
    struct mbr_mount *mnt = fs_node->backing.priv_state;

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            *value = 0;
            break;
        case FS_NODE_ATTR_TYPES:
            *value = FS_NODE_TYPE_DIRECTORY;
            break;
        default:
            return -EINVAL;
    }

    return 0;
}

static int
mbr_root_dir_setattr(
        struct fs_node *fs_node,
        int attr,
        size_t value)
{
    struct mbr_mount *mnt = fs_node->backing.priv_state;

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
	    if(value == 0) {
                return 0;
	    } else {
		return -EINVAL;
	    }
	    break;
    }

    return -EINVAL;
}

static int
mbr_root_dir_lookup(
	struct fs_node *fs_node,
	const char *name,
	size_t *inode,
	char *sym_buffer,
	size_t sym_buflen)
{
    int res;
    struct mbr_mount *mnt = fs_node->backing.priv_state;

    long index = parse_long(name,  -1L);

    struct mbr_partition_entry entry;
    res = mbr_mount_load_partition_entry(mnt, index, &entry);
    if(res) {
	return res;
    }

    if(letoh32(entry.lba_count) == 0) {
	return -ENXIO;
    }

    *inode = index;
    return FS_NODE_LOOKUP_HARD;
}

static struct fs_node_ops
mbr_root_dir_node_ops =
{
    .lookup = mbr_root_dir_lookup,
    .getattr = mbr_root_dir_getattr,
    .setattr = mbr_root_dir_setattr,

    .flush = fs_node_flush_nop,
};
FS_NODE_OPS_INIT_UNDEF(mbr_root_dir_node_ops);

int
mbr_root_dir_begin(
	struct file *file)
{
    int res;

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    struct mbr_mount *mnt = fs_node->backing.priv_state;

    file->dir_offset = 1;
    struct mbr_partition_entry entry;
    res = mbr_mount_load_partition_entry(mnt, file->dir_offset, &entry);
    if(res) {
	file->dir_offset = 0;
	return res;
    }

    return 0;
}

int
mbr_root_dir_next(
	struct file *file)
{
    int res;

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    struct mbr_mount *mnt = fs_node->backing.priv_state;

    if(file->dir_offset == 0) {
	return -EINVAL;
    }

    file->dir_offset++;
    struct mbr_partition_entry entry;
    res = mbr_mount_load_partition_entry(mnt, file->dir_offset, &entry);
    if(res) {
	file->dir_offset = 0;
	return res;
    }
    return 0;
}

int
mbr_root_dir_readattr(
	struct file *file,
	int attr,
	size_t *value)
{
    int res;

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    struct mbr_mount *mnt = fs_node->backing.priv_state;

    if(file->dir_offset == 0) {
	return -EINVAL;
    }

    struct mbr_partition_entry entry;
    res = mbr_mount_load_partition_entry(mnt, file->dir_offset, &entry);
    if(res) {
	file->dir_offset = 0;
	return res;
    }

    return -EUNIMPL;
}

int
mbr_root_dir_readname(
	struct file *file,
	char *buffer,
	size_t buflen)
{
    int res;
    
    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    struct mbr_mount *mnt = fs_node->backing.priv_state;

    if(file->dir_offset == 0) {
	return -EINVAL;
    }

    struct mbr_partition_entry entry;
    res = mbr_mount_load_partition_entry(mnt, file->dir_offset, &entry);
    if(res) {
	file->dir_offset = 0;
	return res;
    }

    snprintk(buffer, buflen, "%lu", file->dir_offset);
    buffer[buflen-1] = '\0';

    return 0;
}

static struct fs_file_ops
mbr_root_dir_file_ops =
{
    .dir_begin = mbr_root_dir_begin,
    .dir_next = mbr_root_dir_next,
    .dir_readattr = mbr_root_dir_readattr,
    .dir_readname = mbr_root_dir_readname,
};
FS_FILE_OPS_INIT_UNDEF(mbr_root_dir_file_ops);

static int
mbr_partition_getattr(
        struct fs_node *fs_node,
        int attr,
        size_t *value)
{
    struct mbr_partition *part = fs_node->backing.priv_state;
    struct mbr_mount *mnt = container_of(fs_node->mount, struct mbr_mount, fs_mount);

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            *value = part->num_sectors << mnt->sector_order;
            break;
	case FS_NODE_ATTR_SECTOR_ORDER:
	    *value = mnt->sector_order;
	    break;
	case FS_NODE_ATTR_PAGE_ORDER:
	    *value = mnt->page_order;
	    break;
        case FS_NODE_ATTR_TYPES:
            *value = FS_NODE_TYPE_REGULAR;
            break;
        default:
            return -EUNIMPL;
    }

    return 0;
}

static int
mbr_partition_setattr(
        struct fs_node *fs_node,
        int attr,
        size_t value)
{
    struct mbr_mount *mnt = fs_node->backing.priv_state;

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
	    return -EINVAL;
    }

    return -EUNIMPL;
}

static int
mbr_unaligned_partition_read_page(
        struct fs_node *fs_node,
        void *page,
        uintptr_t pfn,
        unsigned long flags)
{
    struct mbr_partition *part = fs_node->backing.priv_state;
    struct mbr_mount *mnt = container_of(fs_node->mount, struct mbr_mount, fs_mount);

    size_t offset = (part->sector_offset << mnt->sector_order);
    offset += (pfn << mnt->page_order);

    return fs_node_paged_read(
	    mnt->backing_node,
	    offset,
	    page,
	    1ULL<<mnt->page_order,
	    0);
}

static int
mbr_unaligned_partition_write_page(
        struct fs_node *fs_node,
        void *page,
        uintptr_t pfn,
        unsigned long flags)
{
    struct mbr_partition *part = fs_node->backing.priv_state;
    struct mbr_mount *mnt = container_of(fs_node->mount, struct mbr_mount, fs_mount);

    size_t offset = part->sector_offset << mnt->sector_order;
    offset += pfn << mnt->page_order;

    return fs_node_paged_write(
	    mnt->backing_node,
	    offset,
	    page,
	    1ULL<<mnt->page_order,
	    0);
}

static int
mbr_aligned_partition_load_page(
	struct fs_node *fs_node,
	uintptr_t pfn,
	unsigned long flags,
	void __phys **addr_out)
{
    struct mbr_partition *part = fs_node->backing.priv_state;
    struct mbr_mount *mnt = container_of(fs_node->mount, struct mbr_mount, fs_mount);

    size_t pfn_base = (part->sector_offset << mnt->sector_order) >> mnt->page_order;
    struct fs_page *page = fs_node_get_page(mnt->backing_node, pfn_base + pfn, 0);
    if(page == NULL) {
	return -ENXIO;
    }

    *addr_out = page->paddr;

    return 0;
}

static int
mbr_aligned_partition_unload_page(
	struct fs_node *fs_node,
	uintptr_t pfn,
	unsigned long flags,
	void __phys *addr)
{
    struct mbr_partition *part = fs_node->backing.priv_state;
    struct mbr_mount *mnt = container_of(fs_node->mount, struct mbr_mount, fs_mount);

    size_t pfn_base = (part->sector_offset << mnt->sector_order) >> mnt->page_order;
    struct fs_page *page = fs_node_get_page(mnt->backing_node, pfn_base + pfn, 0);
    if(page == NULL) {
	return -ENXIO;
    }

    DEBUG_ASSERT(page->paddr == addr);

    // Two "puts" to undo the "get" done in "mbr_aligned_partition_load_page"
    fs_node_put_page(mnt->backing_node, page, 1); // Have to assume the page has been modified
    fs_node_put_page(mnt->backing_node, page, 0); 

    return 0;
}

static int
mbr_aligned_partition_flush_page(
	struct fs_node *fs_node,
	uintptr_t pfn,
	unsigned long flags,
	void __phys *addr)
{
    struct mbr_partition *part = fs_node->backing.priv_state;
    struct mbr_mount *mnt = container_of(fs_node->mount, struct mbr_mount, fs_mount);

    size_t pfn_base = (part->sector_offset << mnt->sector_order) >> mnt->page_order;

    return fs_node_flush_page(mnt->backing_node, pfn_base + pfn, flags, addr);
}


static struct fs_node_ops
mbr_unaligned_partition_node_ops =
{
    .flush = fs_node_flush_nop,

    .getattr = mbr_partition_getattr,
    .setattr = mbr_partition_setattr,

    .read_page = mbr_unaligned_partition_read_page,
    .write_page = mbr_unaligned_partition_write_page,

    .load_page = fs_node_load_page_read_alloc,
    .unload_page = fs_node_unload_page_free,
    .flush_page = fs_node_flush_page_write,
};
FS_NODE_OPS_INIT_UNDEF(mbr_unaligned_partition_node_ops);

static struct fs_file_ops
mbr_unaligned_partition_file_ops =
{
    .read = fs_file_paged_read,
    .write = fs_file_paged_write,
    .flush = fs_file_paged_flush,
    .seek = fs_file_paged_seek,
};
FS_FILE_OPS_INIT_UNDEF(mbr_unaligned_partition_file_ops);

static struct fs_node_ops
mbr_aligned_partition_node_ops =
{
    .flush = fs_node_flush_nop,

    .getattr = mbr_partition_getattr,
    .setattr = mbr_partition_setattr,

    .load_page = mbr_aligned_partition_load_page,
    .unload_page = mbr_aligned_partition_unload_page,
    .flush_page = mbr_aligned_partition_flush_page,
};
FS_NODE_OPS_INIT_UNDEF(mbr_aligned_partition_node_ops);

static struct fs_file_ops
mbr_aligned_partition_file_ops =
{
    .read = fs_file_paged_read,
    .write = fs_file_paged_write,
    .flush = fs_file_paged_flush,
    .seek = fs_file_paged_seek,
};
FS_FILE_OPS_INIT_UNDEF(mbr_aligned_partition_file_ops);

static int
mbr_register(void) {
    return register_fs_type(&mbr_fs_type, "mbr");
}

declare_init_desc(fs, mbr_register, "Registering MBR Filesystem");

