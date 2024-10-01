
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/ext2/ext2.h>
#include <kanawha/fs/ext2/node.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>

#define EXT2_DIR_FT_UNKNOWN  0
#define EXT2_DIR_FT_REG_FILE 1
#define EXT2_DIR_FT_DIR      2
#define EXT2_DIR_FT_CHRDEV   3
#define EXT2_DIR_FT_BLKDEV   4
#define EXT2_DIR_FT_FIFO     5
#define EXT2_DIR_FT_SOCK     6
#define EXT2_DIR_FT_SYMLINK  7

struct ext2_linked_dir_entry {
    le32_t inode;
    le16_t rec_len;
    uint8_t name_len;
    uint8_t file_type;
};

static int
ext2_dir_read_at(
        struct fs_node *fs_node,
        size_t offset,
        struct ext2_linked_dir_entry *out)
{
    struct ext2_fs_node *node =
        container_of(fs_node, struct ext2_fs_node, fs_node);

    int res;
    res = fs_node_paged_read(
            fs_node,
            offset,
            out,
            sizeof(struct ext2_linked_dir_entry));
    if(res) {
        return res;
    }

    return 0;
}

static int
ext2_dir_read_cur(
        struct file *file,
        struct ext2_linked_dir_entry *out)
{
    return ext2_dir_read_at(
            file->path->fs_node,
            file->dir_offset,
            out);
}

static int
ext2_dir_begin(
        struct file *file)
{
    int res;
    file->dir_offset = 0;
    return 0;
}

static int
ext2_dir_next(
        struct file *file)
{
    int res;

    struct ext2_linked_dir_entry entry;
    res = ext2_dir_read_cur(file, &entry);
    if(res) {
        return res;
    }
    if(entry.name_len == 0) {
        // Tried to call "next" again after a failure
        // without calling "begin"
        return -EINVAL;
    }

    file->dir_offset += entry.rec_len;

    // Read the next entry
    res = ext2_dir_read_cur(file, &entry);
    if(res) {
        return res;
    }
    if(entry.name_len == 0) {
        // Final entry
        return -ENXIO;
    }

    return 0;
}

static int
ext2_dir_readattr(
        struct file *file,
        int attr,
        size_t *value)
{
    return -EUNIMPL;
}

static int
ext2_dir_readname(
        struct file *file,
        char *buf,
        size_t buflen)
{
    int res;

    struct ext2_linked_dir_entry entry;
    res = ext2_dir_read_cur(file, &entry);
    if(res) {
        return res;
    }
    if(entry.name_len == 0) {
        return -ENXIO;
    }

    struct fs_node *fs_node = file->path->fs_node;

    size_t minlen = buflen < entry.name_len ? buflen : entry.name_len;

    res = fs_node_paged_read(
            fs_node,
            file->dir_offset + sizeof(struct ext2_linked_dir_entry),
            buf,
            minlen);
    if(res) {
        return res;
    }
    if(minlen < buflen) {
        buf[minlen] = '\0';
    }

    return 0;
}

int
ext2_dir_node_lookup(
        struct fs_node *fs_node,
        const char *name,
        size_t *inode)
{
    int res;
    printk("ext2_dir_lookup \"%s\"\n", name);

    size_t len = strlen(name);
    size_t offset = 0;
    struct ext2_linked_dir_entry entry;
    while(1) {
        res = ext2_dir_read_at(
                fs_node,
                offset,
                &entry);
        if(res) {
            return res;
        }

        if(entry.name_len == 0) {
            return -ENXIO;
        }

        if(entry.name_len == len) {
            char buffer[len+1];
            res = fs_node_paged_read(
                    fs_node,
                    offset + sizeof(struct ext2_linked_dir_entry),
                    buffer,
                    len);
            if(res) {
                // Hmmmmmm Something is wrong...
                return res;
            }
            buffer[len] = '\0';

            if(strcmp(buffer, name) == 0)
            {
                // This is the node
                *inode = entry.inode;
                return 0;
            }
        }
        offset += entry.rec_len;
    }
}

struct fs_node_ops
ext2_dir_node_ops = {
    .read_page = ext2_fs_node_read_page,
    .write_page = ext2_fs_node_write_page,
    .getattr = ext2_fs_node_getattr,
    .setattr = ext2_fs_node_setattr,
    .flush = ext2_fs_node_flush,

    .lookup = ext2_dir_node_lookup,

    .mkfile = fs_node_cannot_mkfile,
    .mkfifo = fs_node_cannot_mkfifo,
    .mkdir = fs_node_cannot_mkdir,
    .link = fs_node_cannot_link,
    .symlink = fs_node_cannot_symlink,
    .unlink = fs_node_cannot_unlink,
};



struct fs_file_ops
ext2_dir_file_ops = {
    .read = fs_file_paged_read,
    .write = fs_file_paged_write,
    .seek = fs_file_paged_seek,
    .flush = fs_file_node_flush,

    .dir_next = ext2_dir_next,
    .dir_begin = ext2_dir_begin,
    .dir_readattr = ext2_dir_readattr,
    .dir_readname = ext2_dir_readname,
};
