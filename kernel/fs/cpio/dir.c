
#include <kanawha/fs/cpio/cpio.h>
#include <kanawha/fs/cpio/file.h>
#include <kanawha/fs/cpio/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/assert.h>

static int
cpio_dir_begin(
        struct file *file)
{
    int res;

    file->dir_offset = 0;

    struct fs_node *fs_node = file->path->fs_node;
    struct cpio_dir_node *dir_node =
        container_of(fs_node, struct cpio_dir_node, fs_node);
    struct cpio_mount *mount = dir_node->mnt;

    struct cpio_header hdr;

    res = cpio_read_header(
            mount,
            file->dir_offset,
            &hdr);
    if(res) {
        return res;
    }

    if(hdr.binary.c_magic != CPIO_HEADER_MAGIC) {
        return -EINVAL;
    }

    size_t namesize = hdr.binary.c_namesize;
    char name_buf[namesize+1];

    res = fs_node_paged_read(
            mount->backing_file,
            file->dir_offset + sizeof(struct cpio_header),
            (void*)name_buf,
            namesize,
            0);
    if(res) {
        return res;
    }

    name_buf[namesize] = '\0';

    if(strcmp(name_buf, "TRAILER!!!") == 0) {
        return -ENXIO;
    }

    return 0;
}

static int
cpio_dir_next(
        struct file *file)
{
    int res;

    struct fs_node *fs_node = file->path->fs_node;
    struct cpio_dir_node *dir_node =
        container_of(fs_node, struct cpio_dir_node, fs_node);
    struct cpio_mount *mount = dir_node->mnt;

    struct cpio_header hdr;

    res = cpio_read_header(
            mount,
            file->dir_offset,
            &hdr);
    if(res) {
        return res;
    }

    if(hdr.binary.c_magic != CPIO_HEADER_MAGIC) {
        return -EINVAL;
    }

    size_t namesize = hdr.binary.c_namesize;
    size_t filesize = hdr.binary.c_filesize[1] + ((size_t)hdr.binary.c_filesize[0]<<16);

    file->dir_offset += sizeof(struct cpio_binary_header);
    file->dir_offset += (namesize + 1) & ~1;
    file->dir_offset += (filesize + 1) & ~1;

    // After advancing, read the header of the next file

    res = cpio_read_header(
            mount,
            file->dir_offset,
            &hdr);
    if(res) {
        return res;
    }

    if(hdr.binary.c_magic != CPIO_HEADER_MAGIC) {
        return -EINVAL;
    }

    namesize = hdr.binary.c_namesize;
    char name_buf[namesize+1];

    res = fs_node_paged_read(
            mount->backing_file,
            file->dir_offset + sizeof(struct cpio_header),
            (void*)name_buf,
            namesize,
            0);
    if(res) {
        return res;
    }

    name_buf[namesize] = '\0';

    if(strcmp(name_buf, "TRAILER!!!") == 0) {
        return -ENXIO;
    }

    return 0;
}

static int
cpio_dir_readattr(
        struct file *file,
        int attr,
        size_t *value)
{
    return -EUNIMPL;
}

static int
cpio_dir_readname(
        struct file *file,
        char *buf,
        size_t buflen)
{
    int res;

    struct fs_node *fs_node = file->path->fs_node;
    struct cpio_dir_node *dir_node =
        container_of(fs_node, struct cpio_dir_node, fs_node);
    struct cpio_mount *mount = dir_node->mnt;

    struct cpio_header hdr;

    res = cpio_read_header(
            mount,
            file->dir_offset,
            &hdr);
    if(res) {
        return res;
    }

    size_t namesize = hdr.binary.c_namesize;
    char name_buf[namesize+1];

    res = fs_node_paged_read(
            mount->backing_file,
            file->dir_offset + sizeof(struct cpio_header),
            (void*)name_buf,
            namesize,
            0);
    if(res) {
        return res;
    }

    name_buf[namesize] = '\0';

    strncpy(buf, name_buf, buflen);

    return 0;
}

int
cpio_dir_node_lookup(
        struct fs_node *fs_node,
        const char *name,
        size_t *inode)
{
    int res;

    struct cpio_dir_node *dir_node =
        container_of(fs_node, struct cpio_dir_node, fs_node);
    struct cpio_mount *mount = dir_node->mnt;

    uintptr_t offset = 0;
    int found = 0;
    struct cpio_header hdr;

    while(!found) {
        res = cpio_read_header(
                mount, offset, &hdr);
        if(res) {
            eprintk("Failed to read CPIO file header! (err=%s)\n",
                    errnostr(res));
            return res;
        }

        size_t namesize = hdr.binary.c_namesize;
        char name_buf[namesize+1];

        res = fs_node_paged_read(
                mount->backing_file,
                offset + sizeof(struct cpio_header),
                (void*)name_buf,
                namesize,
                0);
        if(res) {
            eprintk("Failed to read CPIO file name! (err=%s)\n",
                    errnostr(res));
            return res;
        }

        name_buf[namesize] = '\0';

        if(strcmp(name_buf, "TRAILER!!!") == 0) {
            found = 0;
            break;
        }

        if(strcmp(name_buf, name) == 0) {
            found = 1;
            break;
        }
 
        size_t filesize = hdr.binary.c_filesize[1] + ((size_t)hdr.binary.c_filesize[0]<<16);

        offset += sizeof(struct cpio_binary_header);
        offset += (namesize + 1) & ~1;
        offset += (filesize + 1) & ~1;   
    }

    if(!found) {
        return -ENXIO;
    }

    *inode = hdr.binary.c_ino;

    return 0;
}

struct fs_file_ops
cpio_dir_file_ops = {
    .read = fs_file_cannot_read,
    .write = fs_file_cannot_write,
    .seek = fs_file_cannot_seek,
    .flush = fs_file_cannot_flush,

    .dir_next = cpio_dir_next,
    .dir_begin = cpio_dir_begin,
    .dir_readattr = cpio_dir_readattr,
    .dir_readname = cpio_dir_readname,
};

struct fs_node_ops
cpio_dir_node_ops = {
    .read_page = fs_node_cannot_read_page,
    .write_page = fs_node_cannot_write_page,
    .flush = fs_node_cannot_flush,
    .getattr = fs_node_cannot_getattr,
    .setattr = fs_node_cannot_setattr,

    .lookup = cpio_dir_node_lookup,
    .mkfile = fs_node_cannot_mkfile,
    .mkdir = fs_node_cannot_mkdir,
    .link = fs_node_cannot_link,
    .symlink = fs_node_cannot_symlink,
    .unlink = fs_node_cannot_unlink,
};

