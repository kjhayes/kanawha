
#include <kanawha/types.h>
#include <kanawha/endian.h>
#include <kanawha/attribute.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/stddef.h>
#include <kanawha/common.h>

#include <kanawha/fs/type.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>

typedef enum fat_type {
    FAT_TYPE_UNKNOWN,
    FAT_TYPE_FAT12,
    FAT_TYPE_FAT16,
    FAT_TYPE_FAT32,
    FAT_TYPE_EXFAT,
} fat_type_t;

static inline const char *
fat_type_to_string(fat_type_t type) {
    switch(type) {
	case FAT_TYPE_FAT12: return "FAT12";
	case FAT_TYPE_FAT16: return "FAT16";
	case FAT_TYPE_FAT32: return "FAT32";
	case FAT_TYPE_EXFAT: return "exFAT";
	default: return "FAT_TYPE_UNKNOWN";
    }
}

struct __packed bios_param_block {
    uint8_t asm_bytes[3];
    uint8_t oem_id[8];
    le16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    le16_t num_resv_sectors;
    uint8_t num_fats;
    le16_t num_root_dir_entries;
    le16_t num_sectors;
    uint8_t media_descriptor_type;
    le16_t sectors_per_fat;
    le16_t sectors_per_track;
    le16_t num_heads;
    le32_t num_hidden_sectors;
    le32_t num_sectors_large;
};
ASSERT_TYPE_SIZE(struct bios_param_block, 0x24);

#define BOOTABLE_PARTITION_SIGNATURE 0xAA55;

struct __packed ext_boot_record_short {
    uint8_t drive_number;
    uint8_t __resv0;
    uint8_t signature;
    le32_t volume_id;
    uint8_t volume_label[11];
    uint8_t system_label[8];
    uint8_t boot_code[448];
    le16_t bootable_partition_signature;
};
struct __packed ext_boot_record_long {
    le32_t sectors_per_fat;
    le16_t flags;
    le16_t fat_version;
    le32_t root_directory_cluster;
    le16_t fsinfo_sector;
    le16_t backup_boot_sector;
    uint8_t __resv0[12];
    uint8_t drive_number;
    uint8_t __resv1;
    uint8_t signature;
    le32_t volume_id;
    uint8_t volume_label[11];
    uint8_t system_label[8];
    uint8_t boot_code[420];
    le16_t bootable_partition_signature;
};

#define FS_INFO_SIGNATURE_0 0x41615252
#define FS_INFO_SIGNATURE_1 0x61417272
#define FS_INFO_SIGNATURE_2 0xAA550000
struct __packed fsinfo {
    le32_t signature_0;
    uint8_t __resv[480];
    le32_t signature_1;
    le32_t free_cluster_count_hint;
    le32_t avail_cluster_start_hint;
    uint8_t __resv1[12];
    le32_t signature_2;
};
ASSERT_TYPE_SIZE(struct fsinfo, 512);

struct __packed fat12_boot_sector {
    struct bios_param_block bpb;
    struct ext_boot_record_short ebr;
};
ASSERT_TYPE_SIZE(struct fat12_boot_sector, 512);

struct __packed fat16_boot_sector {
    struct bios_param_block bpb;
    struct ext_boot_record_short ebr;
};
ASSERT_TYPE_SIZE(struct fat16_boot_sector, 512);

struct __packed fat32_boot_sector {
    struct bios_param_block bpb;
    struct ext_boot_record_long ebr;
};
ASSERT_TYPE_SIZE(struct fat32_boot_sector, 512);

struct __packed exfat_boot_sector {
    uint8_t asm_bytes[3];
    uint8_t oem_id[8];
    uint8_t mbz[53];
    le64_t partition_offset;
    le64_t volume_length;
    le32_t fat_sector_offset;
    le32_t fat_sector_length;
    le32_t cluster_heap_sector_offset;
    le32_t cluster_count;
    le32_t root_directory_cluster;
    le32_t serial_number;
    le16_t filesystem_revision;
    le16_t flags;
    uint8_t sector_shift;
    uint8_t cluster_shift;
    uint8_t number_of_fats;
    uint8_t drive_select;
    uint8_t percentage_in_use;
    uint8_t __resv0[7];
    uint8_t boot_code[390];
    le16_t bootable_partition_signature;
};
ASSERT_TYPE_SIZE(struct exfat_boot_sector, 512);

#define FAT_CLUSTER_FREE  (0)
#define FAT_CLUSTER_FILE  (1)
#define FAT_CLUSTER_DIR   (2)
#define FAT_CLUSTER_CHAIN (3)

struct fat_mount
{
    struct fs_mount fs_mount;

    order_t media_page_order;
    struct fs_node *media;

    order_t sector_order;
    size_t num_sectors;

    size_t sectors_per_cluster;
    size_t num_clusters;
    uint8_t *cluster_types;

    fat_type_t fat_type;

    size_t root_directory_cluster;
};

struct fat_node
{
    struct fs_node *fs_node;
    size_t inode;
    uint8_t directory_entry[32];
};

static struct fs_node_ops fat_dir_node_ops;
static struct fs_file_ops fat_dir_file_ops;

static struct fs_node_ops fat_file_node_ops;
static struct fs_file_ops fat_file_file_ops;

static inline int
fat_node_is_root(struct fat_node *node)
{
    return node->inode == 0;
}

/*
 * FAT
 */

static inline size_t
read_fat12(struct fat_mount *mnt, size_t index)
{
    // TODO
    return 0;
}
static inline size_t
read_fat16(struct fat_mount *mnt, size_t index)
{
    // TODO
    return 0;
}
static inline size_t
read_fat32(struct fat_mount *mnt, size_t index)
{
    // TODO
    return 0;
}
static inline size_t
read_exfat(struct fat_mount *mnt, size_t index)
{
    // TODO
    return 0;
}

static inline size_t
read_fat(struct fat_mount *mnt, size_t index)
{
    switch(mnt->fat_type) {
	case FAT_TYPE_FAT12:
	    return read_fat12(mnt, index);
	case FAT_TYPE_FAT16:
	    return read_fat16(mnt, index);
	case FAT_TYPE_FAT32:
	    return read_fat32(mnt, index);
	case FAT_TYPE_EXFAT:
	    return read_exfat(mnt, index);
	default:
	    wprintk("read_fat from FAT of unknown type!\n");
	    return 0;
    }
}

static inline void
write_fat12(struct fat_mount *mnt, size_t index, size_t value)
{
    // TODO
}
static inline void
write_fat16(struct fat_mount *mnt, size_t index, size_t value)
{
    // TODO
}
static inline void
write_fat32(struct fat_mount *mnt, size_t index, size_t value)
{
    // TODO
}
static inline void 
write_exfat(struct fat_mount *mnt, size_t index, size_t value)
{
    // TODO
}

static inline void 
write_fat(struct fat_mount *mnt, size_t index, size_t value)
{
    switch(mnt->fat_type) {
	case FAT_TYPE_FAT12:
	    write_fat12(mnt, index, value);
	    return;
	case FAT_TYPE_FAT16:
	    write_fat16(mnt, index, value);
	    return;
	case FAT_TYPE_FAT32:
	    write_fat32(mnt, index, value);
	    return;
	case FAT_TYPE_EXFAT:
	    write_exfat(mnt, index, value);
	    return;
	default:
	    wprintk("write_fat to FAT of unknown type!\n");
	    return;
    }
}

static int
fat_dir_dir_begin(
	struct file *file)
{
    file->dir_offset = 0;
    return -EUNIMPL;
}

static int
fat_dir_dir_next(
	struct file *file)
{
    file->dir_offset += 1;
    return -EUNIMPL;
}

static int
fat_dir_dir_readname(
	struct file *file,
	char *buffer,
	size_t buflen)
{
    return -EUNIMPL;
}

static int
fat_dir_dir_readattr(
	struct file *file,
	int attr,
	size_t *value)
{
    return -EUNIMPL;
}

static int
fat_mount_load_node(
	struct fs_mount *mnt,
	size_t index,
	struct fs_node *fs_node)
{
    if(index == 0) {
	// This is the root inode
	struct fat_node *node = kmalloc(sizeof(struct fat_node));
	if(node == NULL) {
	    return -ENOMEM;
	}
	memset(node, 0, sizeof(*node));

	node->inode = 0;
	node->fs_node = fs_node;

	node->fs_node->backing.priv_state = (void*)node;
	node->fs_node->backing.node_ops = &fat_dir_node_ops;
	node->fs_node->backing.file_ops = &fat_dir_file_ops;

	return 0;
    }

    // TODO
    return -EUNIMPL;
}

static int
fat_mount_unload_node(
	struct fs_mount *mnt,
	size_t index,
	struct fs_node *fs_node)
{
    struct fat_node *node = fs_node->backing.priv_state;

    if(index == 0) {
	// This is the root inode
	kfree(node);
	return 0;
    }

    // TODO
    return -EUNIMPL;
}

static int
fat_mount_root_index(
	struct fs_mount *fs_mount,
	size_t *inode_out)
{
    struct fat_mount *mnt = container_of(fs_mount, struct fat_mount, fs_mount);
    *inode_out = 0; // We denote the root inode as 0 regardless of where it is place in the filesystem
    return 0;
}

static int
fat_mount_sync(
	struct fs_mount *fs_mount)
{
    struct fat_mount *mnt = container_of(fs_mount, struct fat_mount, fs_mount);
    // TODO
    return 0;
}

static struct fs_mount_ops
fat_mount_ops = {
    .sync = fat_mount_sync,
    .load_node = fat_mount_load_node,
    .unload_node = fat_mount_unload_node,
    .root_index = fat_mount_root_index,
};

static int
fat_mount_file(
	struct fs_type *type,
	struct fs_node *fs_node,
	struct fs_mount **out)
{
    int res;

    struct fat_mount *mnt = kmalloc(sizeof(*mnt));
    if(mnt == NULL) {
	return -ENOMEM;
    }
    memset(mnt, 0, sizeof(*mnt));

    init_fs_mount_struct(&mnt->fs_mount, &fat_mount_ops);

    mnt->media = fs_node;
    {
    size_t page_order;
    res = fs_node_getattr(fs_node, FS_NODE_ATTR_PAGE_ORDER, &page_order);
    if(res) {
	kfree(mnt);
	return res;
    }
    mnt->media_page_order = page_order;
    if(mnt->media_page_order < 9) {
	kfree(mnt);
	return -EINVAL;
    }
    }

    void *buffer = kmalloc(512);
    if(buffer == NULL) {
	kfree(mnt);
	return -ENOMEM;
    }
    memset(buffer, 0, 512);

    { // Read the first "sector" (not actually sure how large a sector is yet)
      struct fs_page *boot_pg = fs_node_get_page(mnt->media, 0, 0);
      if(boot_pg == NULL) {
          kfree(mnt);
	  kfree(buffer);
          return -EINVAL;
      }
      DEBUG_ASSERT(boot_pg->order >= 9);
      memcpy_pv(buffer, boot_pg->paddr, 512);
      fs_node_put_page(mnt->media, boot_pg, 0);
    }

    struct bios_param_block *bpb = buffer;
    struct exfat_boot_sector *exfat_bs = buffer;
    struct fat12_boot_sector *fat12_bs = buffer;
    struct fat16_boot_sector *fat16_bs = buffer;
    struct fat32_boot_sector *fat32_bs = buffer;

    if(bpb->bytes_per_sector == 0) {
        mnt->fat_type = FAT_TYPE_EXFAT;
	mnt->num_sectors = letoh64(exfat_bs->volume_length);
	mnt->num_clusters = letoh32(exfat_bs->cluster_count);
	mnt->sector_order = exfat_bs->sector_shift;
	mnt->sectors_per_cluster = 1ULL<<exfat_bs->cluster_shift;
    } else {
	mnt->num_sectors = letoh16(bpb->num_sectors);
	if(mnt->num_sectors == 0) {
	    mnt->num_sectors = letoh32(bpb->num_sectors_large);
	}
	DEBUG_ASSERT(mnt->num_sectors > 0);

	mnt->sectors_per_cluster = bpb->sectors_per_cluster;
	mnt->num_clusters = mnt->num_sectors / mnt->sectors_per_cluster;
	if(mnt->num_clusters < 4085) {
	    mnt->fat_type = FAT_TYPE_FAT12;
	} else if(mnt->num_clusters < 65525) {
	    mnt->fat_type = FAT_TYPE_FAT16;
	} else {
	    mnt->fat_type = FAT_TYPE_FAT32;
	}
    }

    // Check signatures
    switch(mnt->fat_type) {
	case FAT_TYPE_FAT12:
	    if(!(fat12_bs->ebr.signature == 0x28 || fat12_bs->ebr.signature == 0x29)) {
		kfree(buffer);
		kfree(mnt);
		return -EINVAL;
	    }
	    break;
	case FAT_TYPE_FAT16:
	    if(!(fat16_bs->ebr.signature == 0x28 || fat16_bs->ebr.signature == 0x29)) {
		kfree(buffer);
		kfree(mnt);
		return -EINVAL;
	    }
	    break;
	case FAT_TYPE_FAT32:
	    if(!(fat32_bs->ebr.signature == 0x28 || fat32_bs->ebr.signature == 0x29)) {
		kfree(buffer);
		kfree(mnt);
		return -EINVAL;
	    }
	    break;
	case FAT_TYPE_EXFAT:
	    break;
	default:
	    unreachable();
    }

    char system_id_str[9];
    switch(mnt->fat_type) {
	case FAT_TYPE_FAT12:
	    memcpy(system_id_str, fat12_bs->ebr.system_label, 8);
	    system_id_str[8] = '\0';
	    break;
	case FAT_TYPE_FAT16:
	    memcpy(system_id_str, fat16_bs->ebr.system_label, 8);
	    system_id_str[8] = '\0';
	    break;
	case FAT_TYPE_FAT32:
	    memcpy(system_id_str, fat32_bs->ebr.system_label, 8);
	    system_id_str[8] = '\0';
	    break;
	case FAT_TYPE_EXFAT:
	    strncpy(system_id_str, "exFAT   ", 8);
	    system_id_str[8] = '\0';
	    break;
	default:
	    unreachable();
    }

    // Determine where the root directory is.
    switch(mnt->fat_type) {
	case FAT_TYPE_FAT12:
	case FAT_TYPE_FAT16:
	    kfree(buffer);
	    kfree(mnt);
	    return -EUNIMPL; // TODO
	    break;
	case FAT_TYPE_FAT32:
	    mnt->root_directory_cluster = letoh32(fat32_bs->ebr.root_directory_cluster);
	    break;
	case FAT_TYPE_EXFAT:
	    mnt->root_directory_cluster = letoh32(exfat_bs->root_directory_cluster);
	    break;
	default:
	    unreachable();
    }

    kfree(buffer);

    printk("Found Mount of Type %s System ID = %s, num_clusters=0x%lx\n",
	    fat_type_to_string(mnt->fat_type),
	    system_id_str,
	    (unsigned long)mnt->num_clusters);

    *out = &mnt->fs_mount;

    return 0;
};

static int
fat_unmount(
	struct fs_type *type,
	struct fs_mount *mnt)
{
    return -EUNIMPL;
}

static struct fs_type
fat_fs_type = {
    .mount_file = fat_mount_file,
    .mount_special= fs_type_cannot_mount_special,
    .unmount = fat_unmount,
};
static int
register_fat_fs_type(void)
{
    int res;
    res = register_fs_type(
	    &fat_fs_type,
	    "fat");
    if(res) {
	return res;
    }
    return 0;
}
declare_init_desc(fs, register_fat_fs_type, "Registering FAT Filesystem");

static struct fs_node_ops
fat_dir_node_ops = {
    .link = fs_node_cannot_link,
    .unlink = fs_node_cannot_unlink,
    .symlink = fs_node_cannot_symlink,
    .lookup = fs_node_cannot_lookup,
    .mkdir = fs_node_cannot_mkdir,
    .mkfifo = fs_node_cannot_mkfifo,
    .mkfile = fs_node_cannot_mkfile,
    .getattr = fs_node_cannot_getattr,
    .setattr = fs_node_cannot_setattr,
    .load_page = fs_node_cannot_load_page,
    .unload_page = fs_node_cannot_unload_page,
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_write_page,
    .flush = fs_node_cannot_flush,
    .flush_page = fs_node_cannot_flush_page,
};
static struct fs_file_ops
fat_dir_file_ops = {
    .dir_begin = fat_dir_dir_begin,
    .dir_next = fat_dir_dir_next,
    .dir_readattr = fat_dir_dir_readattr,
    .dir_readname = fat_dir_dir_readname,

    .read = fs_file_cannot_read,
    .write = fs_file_cannot_write,
    .seek = fs_file_cannot_seek,
    .flush = fs_file_cannot_flush,
    .poll = fs_file_cannot_poll,
};

static struct fs_node_ops
fat_file_node_ops = {
    .link = fs_node_cannot_link,
    .unlink = fs_node_cannot_unlink,
    .symlink = fs_node_cannot_symlink,
    .lookup = fs_node_cannot_lookup,
    .mkdir = fs_node_cannot_mkdir,
    .mkfifo = fs_node_cannot_mkfifo,
    .mkfile = fs_node_cannot_mkfile,
    .getattr = fs_node_cannot_getattr,
    .setattr = fs_node_cannot_setattr,
    .load_page = fs_node_cannot_load_page,
    .unload_page = fs_node_cannot_unload_page,
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_write_page,
    .flush = fs_node_cannot_flush,
    .flush_page = fs_node_cannot_flush_page,
};
static struct fs_file_ops
fat_file_file_ops = {
    .read = fs_file_cannot_read,
    .write = fs_file_cannot_write,
    .seek = fs_file_cannot_seek,
    .flush = fs_file_cannot_flush,
    .dir_begin = fs_file_cannot_dir_begin,
    .dir_next = fs_file_cannot_dir_next,
    .dir_readattr = fs_file_cannot_dir_readattr,
    .dir_readname = fs_file_cannot_dir_readname,
    .poll = fs_file_cannot_poll,
};
