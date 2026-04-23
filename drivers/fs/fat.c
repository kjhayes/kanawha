
#include <kanawha/attribute.h>
#include <kanawha/common.h>
#include <kanawha/endian.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/types.h>

#include <kanawha/fs/file.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/type.h>

typedef enum fat_type
{
    FAT_TYPE_UNKNOWN,
    FAT_TYPE_FAT12,
    FAT_TYPE_FAT16,
    FAT_TYPE_FAT32,
    FAT_TYPE_EXFAT,
} fat_type_t;

__maybe_unused static inline const char *
fat_type_to_string(fat_type_t type)
{
    switch(type)
    {
    case FAT_TYPE_FAT12:
        return "FAT12";
    case FAT_TYPE_FAT16:
        return "FAT16";
    case FAT_TYPE_FAT32:
        return "FAT32";
    case FAT_TYPE_EXFAT:
        return "exFAT";
    default:
        return "FAT_TYPE_UNKNOWN";
    }
}

struct __packed bios_param_block
{
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

struct __packed ext_boot_record_short
{
    uint8_t drive_number;
    uint8_t __resv0;
    uint8_t signature;
    le32_t volume_id;
    uint8_t volume_label[11];
    uint8_t system_label[8];
    uint8_t boot_code[448];
    le16_t bootable_partition_signature;
};
struct __packed ext_boot_record_long
{
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
struct __packed fsinfo
{
    le32_t signature_0;
    uint8_t __resv[480];
    le32_t signature_1;
    le32_t free_cluster_count_hint;
    le32_t avail_cluster_start_hint;
    uint8_t __resv1[12];
    le32_t signature_2;
};
ASSERT_TYPE_SIZE(struct fsinfo, 512);

struct __packed fat12_boot_sector
{
    struct bios_param_block bpb;
    struct ext_boot_record_short ebr;
};
ASSERT_TYPE_SIZE(struct fat12_boot_sector, 512);

struct __packed fat16_boot_sector
{
    struct bios_param_block bpb;
    struct ext_boot_record_short ebr;
};
ASSERT_TYPE_SIZE(struct fat16_boot_sector, 512);

struct __packed fat32_boot_sector
{
    struct bios_param_block bpb;
    struct ext_boot_record_long ebr;
};
ASSERT_TYPE_SIZE(struct fat32_boot_sector, 512);

struct __packed exfat_boot_sector
{
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

#define FAT_DIRENT_ATTR_READ_ONLY (0x01)
#define FAT_DIRENT_ATTR_HIDDEN (0x02)
#define FAT_DIRENT_ATTR_SYSTEM (0x04)
#define FAT_DIRENT_ATTR_VOLUME_ID (0x08)
#define FAT_DIRENT_ATTR_DIRECTORY (0x10)
#define FAT_DIRENT_ATTR_ARCHIVE (0x20)
#define FAT_DIRENT_ATTR_LFN (0x0F)

#define EXFAT_DIRENT_TYPE_FILE (0x85)
#define EXFAT_DIRENT_TYPE_STREAM (0xC0)
#define EXFAT_DIRENT_TYPE_NAME (0xC1)

struct __packed fat_dirent
{
    union __packed
    {
        struct __packed
        {
            union __packed
            {
                uint8_t type;
                struct __packed
                {
                    uint8_t name[8];
                    uint8_t extension[3];
                    uint8_t attr;
                    uint8_t __resv;
                    uint8_t ct_centsec;
                    le16_t ct_hrminsec;
                    le16_t ct_date;
                    le16_t at_date;
                    le16_t cluster_high;
                    le16_t mt_hrminsec;
                    le16_t mt_date;
                    le16_t cluster_low;
                    le32_t byte_size;
                };
            };
        } fat;
        union __packed
        {
            uint8_t type;
            struct __packed
            {
                uint8_t type;
                uint8_t secondary_entry_count;
                le16_t entry_checksum;
                le16_t attr;
                le16_t __resv;
                le32_t ct_datetime;
                le32_t mt_datetime;
                le32_t at_datetime;
                uint8_t ct_centsec;
                uint8_t mt_centsec;
                uint8_t ct_utc_offset;
                uint8_t mt_utc_offset;
                uint8_t at_utc_offset;
            } file;
            struct __packed
            {
                uint8_t type;
                uint8_t flags;
                uint8_t __resv0;
                uint8_t namelen;
                le16_t namehash;
                uint16_t __resv1;
                le64_t valid_datalen;
                uint32_t __resv2;
                le32_t cluster;
                le64_t datalen;
            } stream;
            struct __packed
            {
                uint8_t type;
                uint8_t flags;
                le16_t utf16_name[15];
            } name;
        } exfat;
    };
};
ASSERT_TYPE_SIZE(struct fat_dirent, 32);

struct fat_mount
{
    struct fs_mount fs_mount;

    order_t media_page_order;
    struct fs_node *media;

    order_t sector_order;
    size_t num_sectors;

    size_t cluster_order;

    size_t num_clusters;
    uint8_t *cluster_types;

    fat_type_t fat_type;

    size_t num_fats;
    size_t fat_sector_offset;
    size_t fat_num_sectors;

    size_t data_sector_offset;
    size_t data_num_sectors;

    size_t root_directory_cluster;
};

static int
fat_mount_media_read(struct fat_mount *mnt,
                     size_t offset,
                     void *buffer,
                     size_t buflen)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(mnt));
    DEBUG_ASSERT(KERNEL_ADDR(mnt->media));

    dprintk("fat_mount_media_read(mnt=%p, offset=0x%lx, buffer=%p, "
            "buflen=0x%lx) starting\n",
            mnt,
            offset,
            buffer,
            buflen);
    res = fs_node_paged_read(mnt->media, offset, buffer, buflen, 0);
    dprintk("fat_mount_media_read(mnt=%p, offset=0x%lx, buffer=%p, "
            "buflen=0x%lx) complete\n",
            mnt,
            offset,
            buffer,
            buflen);
    return res;
}

static int
fat_mount_media_write(struct fat_mount *mnt,
                      size_t offset,
                      void *buffer,
                      size_t buflen)
{
    return fs_node_paged_write(mnt->media, offset, buffer, buflen, 0);
}

static inline int
fat_dirent_is_inode(struct fat_mount *mnt, struct fat_dirent *dirent)
{
    if(mnt->fat_type == FAT_TYPE_EXFAT)
    {
        return dirent->exfat.type == EXFAT_DIRENT_TYPE_FILE;
    }
    else
    {
        if(dirent->fat.type == 0x00)
        {
            return 0;
        }
        if(dirent->fat.type == 0xE5)
        {
            return 0;
        }
        return (dirent->fat.attr & FAT_DIRENT_ATTR_LFN) != FAT_DIRENT_ATTR_LFN;
    }
}

static inline int
fat_dirent_readname(struct fat_mount *mnt,
                    struct fat_dirent *dirent,
                    char *buffer,
                    size_t buflen)
{
    if(mnt->fat_type == FAT_TYPE_EXFAT)
    {
        return -EUNIMPL; // TODO
    }
    else
    {
        if((dirent->fat.attr & FAT_DIRENT_ATTR_LFN) == FAT_DIRENT_ATTR_LFN)
        {
            // TODO handle long names
            return -EUNIMPL;
        }

        char namebuf[9];
        memcpy(namebuf, dirent->fat.name, 8);
        namebuf[8] = '\0';
        for(int i = 7; i >= 0; i--)
        {
            if(namebuf[i] == ' ')
            {
                namebuf[i] = '\0';
            }
            else
            {
                break;
            }
        }

        char extbuf[4];
        memcpy(extbuf, dirent->fat.extension, 3);
        extbuf[3] = '\0';
        for(int i = 2; i >= 0; i--)
        {
            if(extbuf[i] == ' ')
            {
                extbuf[i] = '\0';
            }
            else
            {
                break;
            }
        }

        snprintk(buffer, buflen, "%s.%s", namebuf, extbuf);

        return 0;
    }
}

static inline int
fat_dirent_compare_name(struct fat_mount *mnt,
                        struct fat_dirent *dirent,
                        const char *name)
{
    char buffer[64];
    fat_dirent_readname(mnt, dirent, buffer, 64);
    buffer[63] = '\0';

    return strncasecmp(buffer, name, 64);
}

struct fat_node
{
    struct fat_mount *mnt;
    struct fs_node *fs_node;
    size_t inode;
    struct fat_dirent dirent;
};

static struct fs_node_ops fat_dir_node_ops;
static struct fs_file_ops fat_dir_file_ops;

static struct fs_node_ops fat_file_node_ops;
static struct fs_file_ops fat_file_file_ops;

/*
 * FAT
 */

#define FAT_ENTRY_FREE (0)
#define FAT_ENTRY_BAD (1)
#define FAT_ENTRY_END (~0ULL)

static inline int
read_fat12(struct fat_mount *mnt, size_t index, uintptr_t *out)
{
    // TODO
    return -EUNIMPL;
}
static inline int
read_fat16(struct fat_mount *mnt, size_t index, uintptr_t *out)
{
    // TODO
    return -EUNIMPL;
}

static inline int
read_fat32(struct fat_mount *mnt, size_t index, uintptr_t *out)
{
    int res;

    size_t fat_offset = mnt->fat_sector_offset << mnt->sector_order;
    size_t fat_size = mnt->fat_num_sectors << mnt->sector_order;
    size_t entries = fat_size / 4;

    if(index >= entries)
    {
        return -EINVAL;
    }

    le32_t entry_le;
    res = fat_mount_media_read(mnt, fat_offset + (index * 4), &entry_le, 4);
    if(res)
    {
        return res;
    }

    uint32_t entry = letoh32(entry_le);

    entry &= ~0xF0000000UL;

    if(entry == 0)
    {
        *out = FAT_ENTRY_FREE;
        return 0;
    }
    else if(entry == 0x0FFFFFF7)
    {
        *out = FAT_ENTRY_BAD;
        return 0;
    }
    else if(entry >= 0x0FFFFFF8)
    {
        *out = FAT_ENTRY_END;
        return 0;
    }

    *out = entry;
    return 0;
}

static inline int
read_exfat(struct fat_mount *mnt, size_t index, uintptr_t *out)
{
    int res;

    size_t fat_offset = mnt->fat_sector_offset << mnt->sector_order;
    size_t fat_size = mnt->fat_num_sectors << mnt->sector_order;
    size_t entries = fat_size / 4;

    if(index >= entries)
    {
        return -EINVAL;
    }

    le32_t entry_le;
    res = fat_mount_media_read(mnt, fat_offset + (index * 4), &entry_le, 4);
    if(res)
    {
        return res;
    }

    uint32_t entry = letoh32(entry_le);

    if(entry == 0)
    {
        *out = FAT_ENTRY_FREE;
        return 0;
    }
    else if(entry == 0xFFFFFFF7)
    {
        *out = FAT_ENTRY_BAD;
        return 0;
    }
    else if(entry >= 0xFFFFFFF8)
    {
        *out = FAT_ENTRY_END;
        return 0;
    }

    *out = entry;
    return 0;
}

static inline int
read_fat(struct fat_mount *mnt, size_t index, uintptr_t *out)
{
    switch(mnt->fat_type)
    {
    case FAT_TYPE_FAT12:
        return read_fat12(mnt, index, out);
    case FAT_TYPE_FAT16:
        return read_fat16(mnt, index, out);
    case FAT_TYPE_FAT32:
        return read_fat32(mnt, index, out);
    case FAT_TYPE_EXFAT:
        return read_exfat(mnt, index, out);
    default:
        wprintk("read_fat from FAT of unknown type!\n");
        return -EINVAL;
    }
}

static inline int
write_fat12(struct fat_mount *mnt, size_t index, size_t value)
{
    // TODO
    return -EUNIMPL;
}
static inline int
write_fat16(struct fat_mount *mnt, size_t index, size_t value)
{
    // TODO
    return -EUNIMPL;
}
static inline int
write_fat32(struct fat_mount *mnt, size_t index, size_t value)
{
    // TODO
    return -EUNIMPL;
}
static inline int
write_exfat(struct fat_mount *mnt, size_t index, size_t value)
{
    // TODO
    return -EUNIMPL;
}

__maybe_unused static inline int
write_fat(struct fat_mount *mnt, size_t index, size_t value)
{
    switch(mnt->fat_type)
    {
    case FAT_TYPE_FAT12:
        return write_fat12(mnt, index, value);
    case FAT_TYPE_FAT16:
        return write_fat16(mnt, index, value);
    case FAT_TYPE_FAT32:
        return write_fat32(mnt, index, value);
    case FAT_TYPE_EXFAT:
        return write_exfat(mnt, index, value);
    default:
        wprintk("write_fat to FAT of unknown type!\n");
        return -EINVAL;
    }
}

__maybe_unused static inline int
fat_mount_find_free_cluster(struct fat_mount *mnt, uintptr_t *out)
{
    int res;
    return -EUNIMPL;
}

static inline int
fat_node_is_file(struct fat_node *node)
{
    switch(node->mnt->fat_type)
    {
    case FAT_TYPE_FAT12:
    case FAT_TYPE_FAT16:
    case FAT_TYPE_FAT32:
        return (node->dirent.fat.attr & FAT_DIRENT_ATTR_DIRECTORY) == 0;
    case FAT_TYPE_EXFAT:
        return -EUNIMPL;
    default:
        return -EINVAL;
    }
}
static inline int
fat_node_is_directory(struct fat_node *node)
{
    switch(node->mnt->fat_type)
    {
    case FAT_TYPE_FAT12:
    case FAT_TYPE_FAT16:
    case FAT_TYPE_FAT32:
        return (node->dirent.fat.attr & FAT_DIRENT_ATTR_DIRECTORY) != 0;
    case FAT_TYPE_EXFAT:
        return -EUNIMPL;
    default:
        return -EINVAL;
    }
}

static inline int
fat_node_is_root(struct fat_node *node)
{
    return node->inode == 0;
}

static inline size_t
fat_node_byte_size(struct fat_node *node)
{

    dprintk("node getting byte size!\n");

    switch(node->mnt->fat_type)
    {
    case FAT_TYPE_FAT12:
    case FAT_TYPE_FAT16:
    case FAT_TYPE_FAT32:
        return letoh32(node->dirent.fat.byte_size);
    case FAT_TYPE_EXFAT:
        return 0; // TODO
    default:
        return 0; // Invalid
    }
}

static inline uintptr_t
fat_node_first_cluster(struct fat_node *node)
{
    if(fat_node_is_root(node))
    {
        return node->mnt->root_directory_cluster;
    }
    switch(node->mnt->fat_type)
    {
    case FAT_TYPE_FAT12:
    case FAT_TYPE_FAT16:
    case FAT_TYPE_FAT32:
        return (((uint32_t)letoh16(node->dirent.fat.cluster_high)) << 16) |
               letoh16(node->dirent.fat.cluster_low);
    case FAT_TYPE_EXFAT:
        return -EUNIMPL;
    default:
        return -EINVAL;
    }
    return 0;
}

static inline int
fat_follow_cluster_chain(struct fat_mount *mnt,
                         uintptr_t cluster_from,
                         uintptr_t *cluster_to)
{
    int res;
    size_t value;
    res = read_fat(mnt, cluster_from, &value);
    if(res)
    {
        return res;
    }
    if(value == FAT_ENTRY_END)
    {
        return -ENXIO;
    }
    else if(value == FAT_ENTRY_FREE || value == FAT_ENTRY_BAD)
    {
        return -EINVAL;
    }
    *cluster_to = value;
    return 0;
}

static inline int
fat_node_get_cluster(struct fat_node *node, size_t index, uintptr_t *cluster)
{
    int res;

    uintptr_t cur = fat_node_first_cluster(node);

    while(index > 0)
    {
        uintptr_t next;
        res = fat_follow_cluster_chain(node->mnt, cur, &next);
        if(res)
        {
            return res;
        }
        cur = next;
        index--;
    }

    *cluster = cur;
    return 0;
}

static inline int
fat_node_read_cluster(struct fat_node *node, void *buffer, size_t index)
{
    int res;

    uintptr_t cluster;

    res = fat_node_get_cluster(node, index, &cluster);
    if(res)
    {
        return res;
    }

    size_t data_offset = node->mnt->data_sector_offset
                         << node->mnt->sector_order;
    size_t cluster_size = 1ULL << node->mnt->cluster_order;

    if(((index + 1) * 1ULL << (node->mnt->cluster_order -
                               node->mnt->sector_order) >
        node->mnt->data_num_sectors))
    {
        return -EINVAL;
    }

    res = fat_mount_media_read(node->mnt,
                               data_offset + (((cluster - 2) * cluster_size)),
                               buffer,
                               cluster_size);
    if(res)
    {
        return res;
    }

    return 0;
}

static inline int
fat_node_write_cluster(struct fat_node *node, void *buffer, size_t index)
{
    int res;

    uintptr_t cluster;

    res = fat_node_get_cluster(node, index, &cluster);
    if(res)
    {
        return res;
    }

    size_t data_offset = node->mnt->data_sector_offset
                         << node->mnt->sector_order;
    size_t cluster_size = 1ULL << node->mnt->cluster_order;

    if(((index + 1) * 1ULL << (node->mnt->cluster_order -
                               node->mnt->sector_order)) >
       node->mnt->data_num_sectors)
    {
        return -EINVAL;
    }

    res = fat_mount_media_write(node->mnt,
                                data_offset + ((cluster - 2) * cluster_size),
                                buffer,
                                cluster_size);
    if(res)
    {
        return res;
    }

    return 0;
}

static inline int
fat_dir_read_dirent(struct fat_node *dir,
                    size_t index,
                    struct fat_dirent *buffer)
{
    int res;

    size_t cluster_size = 1ULL << dir->mnt->cluster_order;
    size_t dirent_per_cluster = cluster_size / 32;
    DEBUG_ASSERT(dirent_per_cluster > 0);
    size_t cluster_index = index / dirent_per_cluster;
    size_t index_within_cluster = index % dirent_per_cluster;

    uintptr_t cluster;
    res = fat_node_get_cluster(dir, cluster_index, &cluster);
    if(res)
    {
        return res;
    }

    size_t offset = (dir->mnt->data_sector_offset << dir->mnt->sector_order) +
                    ((cluster - 2) * cluster_size) +
                    (index_within_cluster * 32);
    res = fat_mount_media_read(dir->mnt,
                               offset,
                               buffer,
                               sizeof(struct fat_dirent));
    if(res)
    {
        return res;
    }

    if(dir->mnt->fat_type != FAT_TYPE_EXFAT)
    {
        if(buffer->fat.type == 0x00)
        {
            return -ENXIO;
        }
    }

    return 0;
}

static int
fat_dir_dir_next(struct file *file)
{
    int res;

    struct fat_node *dir = fs_path_get_fs_node(file->path)->backing.priv_state;

    struct fat_dirent dirent;

    do
    {
        file->dir_offset += 1;
        res = fat_dir_read_dirent(dir, file->dir_offset, &dirent);
        if(res)
        {
            return res;
        }
    } while(!fat_dirent_is_inode(dir->mnt, &dirent));

    return 0;
}

static int
fat_dir_dir_begin(struct file *file)
{
    int res;

    struct fat_node *dir = fs_path_get_fs_node(file->path)->backing.priv_state;

    file->dir_offset = 0;

    struct fat_dirent dirent;
    res = fat_dir_read_dirent(dir, 0, &dirent);
    if(res)
    {
        return res;
    }

    if(!fat_dirent_is_inode(dir->mnt, &dirent))
    {
        res = fat_dir_dir_next(file);
        return res;
    }

    return 0;
}

static int
fat_dir_dir_readname(struct file *file, char *buffer, size_t buflen)
{
    int res;

    struct fat_node *dir = fs_path_get_fs_node(file->path)->backing.priv_state;

    struct fat_dirent dirent;
    res = fat_dir_read_dirent(dir, file->dir_offset, &dirent);
    if(res)
    {
        return res;
    }

    return fat_dirent_readname(dir->mnt, &dirent, buffer, buflen);
}

static int
fat_dir_dir_readattr(struct file *file, int attr, size_t *value)
{
    return -EUNIMPL;
}

static int
fat_dir_lookup(struct fs_node *fs_node,
               const char *name,
               size_t *inode,
               char *sym_buffer,
               size_t sym_buflen)
{
    int res;

    struct fat_node *dir = fs_node->backing.priv_state;

    struct fat_dirent dirent;
    size_t index = 0;

    do
    {
        res = fat_dir_read_dirent(dir, index, &dirent);
        if(res)
        {
            return res;
        }
        if(fat_dirent_compare_name(dir->mnt, &dirent, name) == 0)
        {
            // Match!
            size_t cluster_size = 1ULL << dir->mnt->cluster_order;
            size_t dirent_per_cluster = cluster_size / 32;
            size_t cluster_index = index / dirent_per_cluster;
            size_t index_within_cluster = index % dirent_per_cluster;

            uintptr_t cluster;
            res = fat_node_get_cluster(dir, cluster_index, &cluster);
            if(res)
            {
                return res;
            }

            size_t offset =
                (dir->mnt->data_sector_offset << dir->mnt->sector_order) +
                ((cluster - 2) * cluster_size) + (index_within_cluster * 32);
            *inode = offset;
            return FS_NODE_LOOKUP_HARD;
        }
        index++;
    } while(1);
}

static int
fat_file_getattr(struct fs_node *fs_node, int attr, size_t *value)
{
    struct fat_node *node = fs_node->backing.priv_state;

    switch(attr)
    {
    case FS_NODE_ATTR_DATA_SIZE:
        *value = fat_node_byte_size(node);
        break;
    case FS_NODE_ATTR_PAGE_ORDER:
        *value = node->mnt->cluster_order;
        break;
    case FS_NODE_ATTR_TYPES:
        *value = FS_NODE_TYPE_REGULAR;
        break;
    default:
        return -EINVAL;
    }
    return 0;
}

static int
fat_file_read_page(struct fs_node *fs_node,
                   void *page,
                   uintptr_t pfn,
                   unsigned long flags)
{
    int res;
    struct fat_node *node = fs_node->backing.priv_state;

    uintptr_t cluster = pfn;

    res = fat_node_read_cluster(node, page, pfn);
    if(res)
    {
        if(res == -ENXIO && flags & FS_NODE_READ_PAGE_MAY_CREATE)
        {
            // TODO: We need to to extend the file
            return -EUNIMPL;
        }
        else
        {
            return res;
        }
    }

    return 0;
}

static int
fat_file_write_page(struct fs_node *fs_node,
                    void *page,
                    uintptr_t pfn,
                    unsigned long flags)
{
    int res;
    struct fat_node *node = fs_node->backing.priv_state;

    uintptr_t cluster = pfn;

    res = fat_node_write_cluster(node, page, pfn);
    if(res)
    {
        if(res == -ENXIO && flags & FS_NODE_WRITE_PAGE_MAY_CREATE)
        {
            // TODO: We need to to extend the file
            return -EUNIMPL;
        }
        else
        {
            return res;
        }
    }

    return 0;
}

static int
fat_file_flush(struct fs_node *node, unsigned long flags)
{
    // TODO
    return 0;
}

static int
fat_mount_load_node(struct fs_mount *fs_mount,
                    size_t index,
                    struct fs_node *fs_node)
{
    int res;

    struct fat_mount *mnt = container_of(fs_mount, struct fat_mount, fs_mount);

    if(index == 0)
    {
        // This is the root inode
        struct fat_node *node = kzmalloc(sizeof(struct fat_node), KM_KERNEL);
        if(node == NULL)
        {
            return -ENOMEM;
        }

        node->inode = 0;
        node->fs_node = fs_node;
        node->mnt = mnt;

        node->fs_node->backing.priv_state = node;
        node->fs_node->backing.node_ops = &fat_dir_node_ops;
        node->fs_node->backing.file_ops = &fat_dir_file_ops;

        return 0;
    }

    struct fat_node *node = kzmalloc(sizeof(struct fat_node), KM_KERNEL);
    if(node == NULL)
    {
        return -ENOMEM;
    }

    node->inode = index;
    node->fs_node = fs_node;
    node->mnt = mnt;

    // Besides the root directory, we denote inodes by the offset of any files'
    // directory entry (This is a FAT based system so we don't really have
    // inodes)
    uintptr_t dirent_off = index;
    res = fat_mount_media_read(mnt,
                               index,
                               &node->dirent,
                               sizeof(struct fat_dirent));
    if(res)
    {
        kfree(node);
        return res;
    }

    node->fs_node->backing.priv_state = node;

    if(fat_node_is_directory(node))
    {
        node->fs_node->backing.node_ops = &fat_dir_node_ops;
        node->fs_node->backing.file_ops = &fat_dir_file_ops;
    }
    else if(fat_node_is_file(node))
    {
        node->fs_node->backing.node_ops = &fat_file_node_ops;
        node->fs_node->backing.file_ops = &fat_file_file_ops;
    }
    else
    {
        kfree(node);
        return -EINVAL;
    }

    return 0;
}

static int
fat_mount_unload_node(struct fs_mount *mnt,
                      size_t index,
                      struct fs_node *fs_node)
{
    struct fat_node *node = fs_node->backing.priv_state;

    if(index == 0)
    {
        // This is the root inode
        kfree(node);
        return 0;
    }

    kfree(node);

    return 0;
}

static int
fat_mount_root_index(struct fs_mount *fs_mount, size_t *inode_out)
{
    struct fat_mount *mnt = container_of(fs_mount, struct fat_mount, fs_mount);
    *inode_out = 0; // We denote the root inode as 0 regardless of where it is
                    // place in the filesystem
    return 0;
}

static int
fat_mount_sync(struct fs_mount *fs_mount)
{
    struct fat_mount *mnt = container_of(fs_mount, struct fat_mount, fs_mount);
    // TODO
    return 0;
}

static struct fs_mount_ops fat_mount_ops = {
    .sync = fat_mount_sync,
    .load_node = fat_mount_load_node,
    .unload_node = fat_mount_unload_node,
    .root_index = fat_mount_root_index,
};

static int
fat_mount_file(struct fs_type *type,
               struct fs_node *fs_node,
               struct fs_mount **out)
{
    int res;

    struct fat_mount *mnt = kzmalloc(sizeof(*mnt), KM_KERNEL);
    if(mnt == NULL)
    {
        return -ENOMEM;
    }

    init_fs_mount_struct(&mnt->fs_mount, &fat_mount_ops);

    fs_node_get(fs_node);
    mnt->media = fs_node;

    {
        size_t page_order;
        res = fs_node_getattr(fs_node, FS_NODE_ATTR_PAGE_ORDER, &page_order);
        if(res)
        {
            fs_node_put(fs_node);
            kfree(mnt);
            return res;
        }
        mnt->media_page_order = page_order;
        if(mnt->media_page_order < 9)
        {
            fs_node_put(fs_node);
            kfree(mnt);
            return -EINVAL;
        }
    }

    void *buffer = kmalloc(512, KM_KERNEL);
    if(buffer == NULL)
    {
        fs_node_put(fs_node);
        kfree(mnt);
        return -ENOMEM;
    }
    res = fat_mount_media_read(mnt, 0, buffer, 512);
    if(res)
    {
        fs_node_put(fs_node);
        kfree(buffer);
        kfree(mnt);
        return res;
    }

    struct bios_param_block *bpb = buffer;
    struct exfat_boot_sector *exfat_bs = buffer;
    struct fat12_boot_sector *fat12_bs = buffer;
    struct fat16_boot_sector *fat16_bs = buffer;
    struct fat32_boot_sector *fat32_bs = buffer;

    if(bpb->bytes_per_sector == 0)
    {
        mnt->fat_type = FAT_TYPE_EXFAT;
        mnt->num_sectors = letoh64(exfat_bs->volume_length);
        mnt->num_clusters = letoh32(exfat_bs->cluster_count);
        mnt->sector_order = exfat_bs->sector_shift;
        mnt->cluster_order = exfat_bs->cluster_shift;
        mnt->fat_sector_offset = letoh32(exfat_bs->fat_sector_offset);
        mnt->fat_num_sectors = letoh32(exfat_bs->fat_sector_length);
        mnt->num_fats = exfat_bs->number_of_fats;
        mnt->data_num_sectors = mnt->num_clusters
                                << (mnt->cluster_order - mnt->sector_order);
        mnt->data_sector_offset =
            mnt->fat_sector_offset + (mnt->num_fats * mnt->fat_num_sectors);
    }
    else
    {
        if(!is_pow2(letoh16(bpb->bytes_per_sector)))
        {
            fs_node_put(fs_node);
            kfree(buffer);
            kfree(mnt);
            return -EINVAL;
        }
        if(!is_pow2(bpb->sectors_per_cluster))
        {
            fs_node_put(fs_node);
            kfree(buffer);
            kfree(mnt);
            return -EINVAL;
        }
        mnt->sector_order = ptr_orderof(letoh16(bpb->bytes_per_sector));
        mnt->cluster_order =
            ptr_orderof(letoh16(bpb->sectors_per_cluster)) + mnt->sector_order;

        mnt->num_sectors = letoh16(bpb->num_sectors);
        if(mnt->num_sectors == 0)
        {
            mnt->num_sectors = letoh32(bpb->num_sectors_large);
        }
        DEBUG_ASSERT(mnt->num_sectors > 0);

        mnt->fat_sector_offset = letoh16(bpb->num_resv_sectors);
        mnt->fat_num_sectors = letoh16(bpb->sectors_per_fat) > 0
                                   ? letoh16(bpb->sectors_per_fat)
                                   : letoh32(fat32_bs->ebr.sectors_per_fat);

        mnt->num_fats = bpb->num_fats;

        size_t root_directory_entries = letoh16(bpb->num_root_dir_entries);
        size_t root_dir_sectors =
            ((root_directory_entries * sizeof(struct fat_dirent)) +
             ((1ULL << mnt->sector_order) - 1)) >>
            mnt->sector_order;

        mnt->data_sector_offset = mnt->fat_sector_offset +
                                  (mnt->num_fats * mnt->fat_num_sectors) +
                                  root_dir_sectors;
        mnt->data_num_sectors =
            mnt->num_sectors -
            (mnt->fat_sector_offset + (mnt->num_fats * mnt->fat_num_sectors) +
             root_dir_sectors);
        mnt->num_clusters =
            mnt->data_num_sectors >> (mnt->cluster_order - mnt->sector_order);

        if(mnt->num_clusters < 4085)
        {
            mnt->fat_type = FAT_TYPE_FAT12;
        }
        else if(mnt->num_clusters < 65525)
        {
            mnt->fat_type = FAT_TYPE_FAT16;
        }
        else
        {
            mnt->fat_type = FAT_TYPE_FAT32;
        }
    }

    if(mnt->data_sector_offset + mnt->data_num_sectors > mnt->num_sectors)
    {
        wprintk("0x%lx + 0x%lx (0x%lx) > 0x%lx (FAT data region overflows the "
                "disk)\n",
                mnt->data_sector_offset,
                mnt->data_num_sectors,
                mnt->data_sector_offset + mnt->data_num_sectors,
                mnt->num_sectors);
        fs_node_put(fs_node);
        kfree(buffer);
        kfree(mnt);
        return -EINVAL;
    }

    // Check signatures
    switch(mnt->fat_type)
    {
    case FAT_TYPE_FAT12:
        if(!(fat12_bs->ebr.signature == 0x28 ||
             fat12_bs->ebr.signature == 0x29))
        {
            fs_node_put(fs_node);
            kfree(buffer);
            kfree(mnt);
            return -EINVAL;
        }
        break;
    case FAT_TYPE_FAT16:
        if(!(fat16_bs->ebr.signature == 0x28 ||
             fat16_bs->ebr.signature == 0x29))
        {
            fs_node_put(fs_node);
            kfree(buffer);
            kfree(mnt);
            return -EINVAL;
        }
        break;
    case FAT_TYPE_FAT32:
        if(!(fat32_bs->ebr.signature == 0x28 ||
             fat32_bs->ebr.signature == 0x29))
        {
            fs_node_put(fs_node);
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
    switch(mnt->fat_type)
    {
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
    switch(mnt->fat_type)
    {
    case FAT_TYPE_FAT12:
    case FAT_TYPE_FAT16:
        fs_node_put(fs_node);
        kfree(buffer);
        kfree(mnt);
        return -EUNIMPL; // TODO
        break;
    case FAT_TYPE_FAT32:
        mnt->root_directory_cluster =
            letoh32(fat32_bs->ebr.root_directory_cluster);
        break;
    case FAT_TYPE_EXFAT:
        mnt->root_directory_cluster = letoh32(exfat_bs->root_directory_cluster);
        break;
    default:
        unreachable();
    }

    kfree(buffer);

    dprintk("Found Mount of Type %s System ID = %s, num_clusters=0x%lx\n",
            fat_type_to_string(mnt->fat_type),
            system_id_str,
            (unsigned long)mnt->num_clusters);

    *out = &mnt->fs_mount;

    return 0;
};

static int
fat_unmount(struct fs_type *type, struct fs_mount *fs_mount)
{
    struct fat_mount *mnt = container_of(fs_mount, struct fat_mount, fs_mount);
    // fs_node_put(mnt->media);
    // kfree(mnt);
    return -EUNIMPL;
}

static struct fs_type fat_fs_type = {
    .probe = fs_type_probe_always_maybe,
    .mount_file = fat_mount_file,
    .mount_special = fs_type_cannot_mount_special,
    .unmount = fat_unmount,
};
static int
register_fat_fs_type(void)
{
    int res;
    res = register_fs_type(&fat_fs_type, "fat");
    if(res)
    {
        return res;
    }
    return 0;
}
declare_init_desc(fs, register_fat_fs_type, "Registering FAT Filesystem");

static struct fs_node_ops fat_dir_node_ops = {
    .lookup = fat_dir_lookup,
};
FS_NODE_OPS_INIT_UNDEF(fat_dir_node_ops);

static struct fs_file_ops fat_dir_file_ops = {
    .dir_begin = fat_dir_dir_begin,
    .dir_next = fat_dir_dir_next,
    .dir_readattr = fat_dir_dir_readattr,
    .dir_readname = fat_dir_dir_readname,
};
FS_FILE_OPS_INIT_UNDEF(fat_dir_file_ops);

static struct fs_node_ops fat_file_node_ops = {
    .getattr = fat_file_getattr,

    .read_page = fat_file_read_page,
    .write_page = fat_file_write_page,
    .flush = fat_file_flush,

    .load_page = fs_node_load_page_read_alloc,
    .unload_page = fs_node_unload_page_free,
    .flush_page = fs_node_flush_page_write,
};
FS_NODE_OPS_INIT_UNDEF(fat_file_node_ops);

static struct fs_file_ops fat_file_file_ops = {
    .read = fs_file_paged_read,
    .write = fs_file_paged_write,
    .seek = fs_file_paged_seek,
    .flush = fs_file_paged_flush,
};
FS_FILE_OPS_INIT_UNDEF(fat_file_file_ops);
