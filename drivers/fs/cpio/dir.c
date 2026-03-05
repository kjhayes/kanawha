
#include <drivers/fs/cpio/cpio.h>
#include <drivers/fs/cpio/file.h>
#include <drivers/fs/cpio/mount.h>
#include <kanawha/assert.h>
#include <kanawha/fs/file.h>
#include <kanawha/fs/node.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>

static int
cpio_dir_begin(struct file *file)
{
    int res;

    file->dir_offset = 0;

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL)
    {
        return -EINVAL;
    }

    struct cpio_dir_node *dir_node = fs_node->backing.priv_state;
    struct cpio_mount *mount = dir_node->mnt;

    struct cpio_header hdr;

    res = cpio_read_header(mount, file->dir_offset, &hdr);
    if(res)
    {
        return res;
    }

    if(hdr.binary.c_magic != CPIO_HEADER_MAGIC)
    {
        return -EINVAL;
    }

    size_t namesize = hdr.binary.c_namesize;
    char name_buf[namesize + 1];

    res = fs_node_paged_read(mount->backing_file,
                             file->dir_offset + sizeof(struct cpio_header),
                             (void *)name_buf,
                             namesize,
                             0);
    if(res)
    {
        return res;
    }

    name_buf[namesize] = '\0';

    if(strcmp(name_buf, "TRAILER!!!") == 0)
    {
        return -ENXIO;
    }

    return 0;
}

static int
cpio_dir_next(struct file *file)
{
    int res;

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL)
    {
        return -EINVAL;
    }

    struct cpio_dir_node *dir_node = fs_node->backing.priv_state;
    struct cpio_mount *mount = dir_node->mnt;

    struct cpio_header hdr;

    res = cpio_read_header(mount, file->dir_offset, &hdr);
    if(res)
    {
        return res;
    }

    if(hdr.binary.c_magic != CPIO_HEADER_MAGIC)
    {
        return -EINVAL;
    }

    size_t namesize = hdr.binary.c_namesize;
    size_t filesize =
        hdr.binary.c_filesize[1] + ((size_t)hdr.binary.c_filesize[0] << 16);

    file->dir_offset += sizeof(struct cpio_binary_header);
    file->dir_offset += (namesize + 1) & ~1;
    file->dir_offset += (filesize + 1) & ~1;

    // After advancing, read the header of the next file

    res = cpio_read_header(mount, file->dir_offset, &hdr);
    if(res)
    {
        return res;
    }

    if(hdr.binary.c_magic != CPIO_HEADER_MAGIC)
    {
        return -EINVAL;
    }

    namesize = hdr.binary.c_namesize;
    char name_buf[namesize + 1];

    res = fs_node_paged_read(mount->backing_file,
                             file->dir_offset + sizeof(struct cpio_header),
                             (void *)name_buf,
                             namesize,
                             0);
    if(res)
    {
        return res;
    }

    name_buf[namesize] = '\0';

    if(strcmp(name_buf, "TRAILER!!!") == 0)
    {
        return -ENXIO;
    }

    return 0;
}

static int
cpio_dir_readattr(struct file *file, int attr, size_t *value)
{
    return -EUNIMPL;
}

static int
cpio_dir_readname(struct file *file, char *buf, size_t buflen)
{
    int res;

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL)
    {
        return -EINVAL;
    }

    struct cpio_dir_node *dir_node = fs_node->backing.priv_state;
    struct cpio_mount *mount = dir_node->mnt;

    struct cpio_header hdr;

    res = cpio_read_header(mount, file->dir_offset, &hdr);
    if(res)
    {
        return res;
    }

    size_t namesize = hdr.binary.c_namesize;
    char name_buf[namesize + 1];

    res = fs_node_paged_read(mount->backing_file,
                             file->dir_offset + sizeof(struct cpio_header),
                             (void *)name_buf,
                             namesize,
                             0);
    if(res)
    {
        return res;
    }

    name_buf[namesize] = '\0';

    strncpy(buf, name_buf, buflen);

    return 0;
}

int
cpio_dir_node_lookup(struct fs_node *fs_node,
                     const char *name,
                     size_t *inode,
                     char *sym_buffer,
                     size_t sym_buflen)
{
    int res;

    struct cpio_dir_node *dir_node = fs_node->backing.priv_state;
    struct cpio_mount *mount = dir_node->mnt;

    uintptr_t offset = 0;
    int found = 0;
    struct cpio_header hdr;

    while(!found)
    {
        res = cpio_read_header(mount, offset, &hdr);
        if(res)
        {
            eprintk("Failed to read CPIO file header! (err=%s)\n",
                    errnostr(res));
            return res;
        }

        size_t namesize = hdr.binary.c_namesize;
        char name_buf[namesize + 1];

        res = fs_node_paged_read(mount->backing_file,
                                 offset + sizeof(struct cpio_header),
                                 (void *)name_buf,
                                 namesize,
                                 0);
        if(res)
        {
            eprintk("Failed to read CPIO file name! (err=%s)\n", errnostr(res));
            return res;
        }

        name_buf[namesize] = '\0';

        if(strcmp(name_buf, "TRAILER!!!") == 0)
        {
            found = 0;
            break;
        }

        if(strcmp(name_buf, name) == 0)
        {
            found = 1;
            break;
        }

        size_t filesize =
            hdr.binary.c_filesize[1] + ((size_t)hdr.binary.c_filesize[0] << 16);

        offset += sizeof(struct cpio_binary_header);
        offset += (namesize + 1) & ~1;
        offset += (filesize + 1) & ~1;
    }

    if(!found)
    {
        return -ENXIO;
    }

    *inode = hdr.binary.c_ino;

    return 0;
}

struct fs_file_ops cpio_dir_file_ops = {
    .dir_next = cpio_dir_next,
    .dir_begin = cpio_dir_begin,
    .dir_readattr = cpio_dir_readattr,
    .dir_readname = cpio_dir_readname,
};
FS_FILE_OPS_INIT_UNDEF(cpio_dir_file_ops);

struct fs_node_ops cpio_dir_node_ops = {
    .flush = fs_node_flush_nop,
    .lookup = cpio_dir_node_lookup,
};
FS_NODE_OPS_INIT_UNDEF(cpio_dir_node_ops);
