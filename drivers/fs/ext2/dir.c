
#include <kanawha/fs/node.h>
#include <kanawha/fs/file.h>
#include <drivers/fs/ext2/ext2.h>
#include <drivers/fs/ext2/node.h>
#include <drivers/fs/ext2/mount.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/irq.h>

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
    struct ext2_fs_node *node = fs_node->backing.priv_state;

    int res;
    res = fs_node_paged_read(
            fs_node,
            offset,
            out,
            sizeof(struct ext2_linked_dir_entry),
            0);
    if(res) {
        return res;
    }

    return 0;
}

static int
ext2_dir_write_at(
        struct fs_node *fs_node,
        size_t offset,
        struct ext2_linked_dir_entry *out)
{
    struct ext2_fs_node *node = fs_node->backing.priv_state;

    int res;
    res = fs_node_paged_write(
            fs_node,
            offset,
            out,
            sizeof(struct ext2_linked_dir_entry),
            FS_NODE_PAGED_WRITE_MAY_EXTEND);
    if(res) {
        return res;
    }

    return 0;
}

// Lock on the parent_node should not be held
static int
ext2_dir_add_linked_entry(
	struct fs_node *backing_node,
        struct ext2_fs_node *parent_node,
        size_t inode,
        uint8_t file_type,
        const char *name)
{
    int res;

    if(inode == 0) {
        wprintk("ext2_dir_add_linked_entry: request to add link to reserved inode=0! (name=%s)\n",
                name);
        return -EINVAL;
    }

    spin_lock(&parent_node->dir_lock);

    size_t namelen = strlen(name);

    size_t min_len_req = namelen + 8;

    // Round up to the nearest multiple of 4
    min_len_req += 0b11;
    min_len_req &= ~0b11;

    struct ext2_linked_dir_entry entry;

    size_t offset = 0;
    ssize_t prev_offset = -1;

    // Go to the end of the directory list
    //
    // In theory there could be gaps in the directory (where rec_len > namelen)
    // but for now we won't try to fit inside those.
    while(1) {
        res = ext2_dir_read_at(backing_node, offset, &entry);
        if(res) {
            // Failed to read (probably at the end of the list
            break;
        }

        if(entry.rec_len == 0) {
            break; // Definitely at the end of the list
        }

        prev_offset = offset;
        offset += entry.rec_len;
    }

    // Align the offset to 4 bytes
    offset += 0b11;
    offset &= ~0b11;

    // Determine how much room we currently have
    size_t offset_block_no = offset / parent_node->mount->block_size;
    size_t offset_into_block = offset - (parent_node->mount->block_size * offset_block_no);
    size_t room_left_in_block = parent_node->mount->block_size - offset_into_block;

    if(room_left_in_block < min_len_req) {
        // If there is not enough room left in the block, move to the next block offset.

        if(prev_offset > 0) {
             // We need to patch the previous entry to extend the rec_len
             // filling out the entire block
             struct ext2_linked_dir_entry prev;
             res = ext2_dir_read_at(backing_node, prev_offset, &prev);
             if(res) {
                 return res;
             }
             prev.rec_len += room_left_in_block;
             res = ext2_dir_write_at(backing_node, prev_offset, &prev);
             if(res) {
                 return res;
             }
        }

        offset_block_no += 1;
        offset_into_block = 0;
        offset = offset_block_no * parent_node->mount->block_size;
        room_left_in_block = parent_node->mount->block_size;
    }

    entry.rec_len = min_len_req;
    entry.name_len = namelen;
    entry.inode = inode;
    entry.file_type = file_type;

    // Write the name first, because if we fail later on,
    // we don't need to overwrite the name (it doesn't actually matter)
    res = fs_node_paged_write(
        backing_node,
        offset+8,
        (void*)name,
        namelen,
        FS_NODE_PAGED_WRITE_MAY_EXTEND);
    if(res) {
        return res;
    }

    res = ext2_dir_write_at(backing_node, offset, &entry);
    if(res) {
        return res;
    }

    spin_unlock(&parent_node->dir_lock);
    return 0;
}

static int
ext2_dir_read_cur(
        struct file *file,
        struct ext2_linked_dir_entry *out)
{
    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -EINVAL;
    }
    return ext2_dir_read_at(
            fs_node,
            file->dir_offset,
            out);
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
    if(entry.rec_len == 0) {
        // Tried to call "next" again after a failure
        // without calling "begin"
        return -EINVAL;
    }

    while(1) {
      size_t next_offset = file->dir_offset + entry.rec_len;
      file->dir_offset = next_offset;

      // Read the next entry
      res = ext2_dir_read_cur(file, &entry);
      if(res) {
          return res;
      }
      if(entry.rec_len == 0) {
          // Final entry
          return -ENXIO;
      }

      if(entry.name_len == 0 || entry.inode == 0) {
          // Skip over an invalid entry
          continue;
      }

      break;
    }

    return 0;
}

static int
ext2_dir_begin(
        struct file *file)
{
    int res;
    file->dir_offset = 0;

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);

    struct ext2_linked_dir_entry entry;
    res = ext2_dir_read_at(fs_node, 0, &entry);
    if(res) {
        return res;
    }

    if(entry.inode == 0) {
        ext2_dir_next(file);
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

    struct fs_node *fs_node = fs_path_get_fs_node(file->path);
    if(fs_node == NULL) {
        return -EINVAL;
    }

    size_t minlen = buflen < entry.name_len ? buflen : entry.name_len;

    res = fs_node_paged_read(
            fs_node,
            file->dir_offset + sizeof(struct ext2_linked_dir_entry),
            buf,
            minlen,
            0);
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
    dprintk("ext2_dir_lookup \"%s\"\n", name);

    size_t len = strlen(name);
    size_t offset = 0;
    struct ext2_linked_dir_entry entry;
    while(1) {
        dprintk("ext2_dir_node_lookup: checking directory entry at offset=%p\n",
                offset);
        res = ext2_dir_read_at(
                fs_node,
                offset,
                &entry);
        if(res) {
            return res;
        }

        if(entry.rec_len == 0) {
            return -ENXIO;
        }

        if(entry.inode != 0 && entry.name_len == len) {
            char buffer[len+1];
            res = fs_node_paged_read(
                    fs_node,
                    offset + sizeof(struct ext2_linked_dir_entry),
                    buffer,
                    len,
                    0);
            if(res) {
                // Hmmmmmm Something is wrong...
                return res;
            }
            buffer[len] = '\0';

            if(strcmp(buffer, name) == 0)
            {
                // This is the node
                *inode = entry.inode;
                dprintk("ext2_dir_lookup \"%s\" FOUND inode=%p\n", name, entry.inode);
                return 0;
            }
        }
        offset += entry.rec_len;
    }
}

static int
ext2_dir_mkfile(
        struct fs_node *fs_node,
        const char *filename,
        unsigned long flags)
{
    int res;

    struct ext2_fs_node *node = fs_node->backing.priv_state;

    dprintk("ext2_dir_mkfile: %s\n",
            filename);

    size_t inode;
    res = ext2_mount_alloc_inode(
            node->mount,
            ext2_fs_node_to_group_num(node),
            &inode);
    if(res) {
        eprintk("EXT2: Failed to allocate inode! (err=%s)\n",
                errnostr(res));
        return res;
    }

    if(inode == 0) {
        wprintk("ext2_dir_mkfile: ext2_mount_alloc_inode returned reserved inode=0!\n");
        return -EINVAL;
    }

    dprintk("Allocated inode: 0x%lx\n", inode);

    struct ext2_inode inode_data;

    memset(&inode_data, 0, sizeof(struct ext2_inode));
    inode_data.links_count = 1;
    inode_data.mode =
        0x8000 // directory
        | (0666); // R/W for everyone
    inode_data.links_count = 1;

    res = ext2_mount_write_inode_data(
            node->mount,
            inode,
            &inode_data);
    if(res) {
        eprintk("EXT2: Failed to write allocated inode! (err=%s)\n",
                errnostr(res));
        return res;
    }

    res = ext2_dir_add_linked_entry(
	    fs_node,
            node,
            inode,
            EXT2_DIR_FT_REG_FILE,
            filename);
    if(res) {
        ext2_mount_free_inode(
                node->mount,
                inode);
        return res;
    }

    fs_node_flush_all_fs_pages(fs_node);

    return 0;
}

static int
ext2_dir_mkdir(
        struct fs_node *parent_fs_node,
        const char *filename,
        unsigned long flags)
{
    int res;

    struct ext2_fs_node *parent_node = parent_fs_node->backing.priv_state;

    printk("ext2_dir_mkdir: %s\n",
            filename);

    size_t group_num = ext2_fs_node_to_group_num(parent_node);

    size_t inode;
    res = ext2_mount_alloc_inode(
            parent_node->mount,
            group_num,
            &inode);
    if(res) {
        eprintk("EXT2: Failed to allocate inode! (err=%s)\n",
                errnostr(res));
        return res;
    }

    if(inode == 0) {
        wprintk("ext2_dir_mkdir: ext2_mount_alloc_inode returned reserved inode=0!\n");
        return -EINVAL;
    }

    dprintk("Allocated inode: 0x%lx\n", inode);

    // TODO: We need to initialize the inode
    struct ext2_inode inode_data;
    res = ext2_mount_read_inode_data(
            parent_node->mount,
            inode,
            &inode_data);
    if(res) {
        eprintk("EXT2: Failed to read allocated inode! (err=%s)\n",
                errnostr(res));
        ext2_mount_free_inode(parent_node->mount, inode);
        return res;
    }

    memset(&inode_data, 0, sizeof(struct ext2_inode));
    inode_data.links_count = 1;
    inode_data.mode =
        0x4000 // directory
        | (0666); // R/W for everyone
    inode_data.links_count = 1;

    res = ext2_mount_write_inode_data(
            parent_node->mount,
            inode,
            &inode_data);
    if(res) {
        eprintk("EXT2: Failed to write allocated inode! (err=%s)\n",
                errnostr(res));
        ext2_mount_free_inode(parent_node->mount, inode);
        return res;
    }

    // Load the newly created directory
    struct fs_node *child_fs_node =
        fs_mount_get_node(&parent_node->mount->fs_mount, inode);

    if(child_fs_node == NULL) {
        eprintk("EXT2: Failed to get fs_node of newly created directory! (err=%s)\n",
                errnostr(res));
        ext2_mount_free_inode(parent_node->mount, inode);
        return res;
    }

    struct ext2_fs_node *child_node = child_fs_node->backing.priv_state;

    res = ext2_dir_add_linked_entry(
	    child_fs_node,
            child_node,
            inode,
            EXT2_DIR_FT_DIR,
            ".");
    if(res) {
        ext2_mount_free_inode(
                parent_node->mount,
                inode);
        return res;
    }

    res = ext2_dir_add_linked_entry(
	    child_fs_node,
            child_node,
            parent_node->inode_index,
            EXT2_DIR_FT_DIR,
            "..");
    if(res) {
        ext2_mount_free_inode(
                parent_node->mount,
                inode);
        return res;
    }
    fs_node_flush_all_fs_pages(child_fs_node);

    // Create a link from the parent directory to the new directory

    res = ext2_dir_add_linked_entry(
	    parent_fs_node,
            parent_node,
            inode,
            EXT2_DIR_FT_DIR,
            filename);
    if(res) {
        eprintk("EXT2: mkdir failed to add linked entry to directory! (err=%s)\n",
                errnostr(res));
        ext2_mount_free_inode(
                parent_node->mount,
                inode);
        return res;
    }
    fs_node_flush_all_fs_pages(parent_fs_node);

    return 0;
}

static int
ext2_dir_unlink(
        struct fs_node *parent_fs_node,
        const char *name)
{
    int res;

    struct ext2_fs_node *parent_node = parent_fs_node->backing.priv_state;

    size_t child_inode;
    res = ext2_dir_node_lookup(
            parent_fs_node,
            name,
            &child_inode);
    if(res) {
        return res;
    }

    return -EUNIMPL;
}

int
ext2_dir_getattr(
        struct fs_node *fs_node,
        int attr,
        size_t *value)
{
    struct ext2_fs_node *node = fs_node->backing.priv_state;

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            *value = ext2_fs_node_inode_size(node);
            break;
        case FS_NODE_ATTR_PAGE_ORDER:
            *value = node->mount->block_order;
            break;
        case FS_NODE_ATTR_TYPES:
            *value = FS_NODE_TYPE_DIRECTORY;
            break;
        default:
            return -EINVAL;
    }

    return 0;
}

int
ext2_dir_setattr(
        struct fs_node *fs_node,
        int attr,
        size_t value)
{
    struct ext2_fs_node *node = fs_node->backing.priv_state;

    switch(attr) {
        case FS_NODE_ATTR_DATA_SIZE:
            return ext2_fs_node_resize(node, value);
    }

    return -EINVAL;
}

struct fs_node_ops
ext2_dir_node_ops = {
    .read_page = ext2_fs_node_read_page,
    .write_page = ext2_fs_node_write_page,

    .load_page = fs_node_load_page_read_alloc,
    .unload_page = fs_node_unload_page_free,
    .flush_page = fs_node_flush_page_write,

    .flush = ext2_fs_node_flush,

    .getattr = ext2_dir_getattr,
    .setattr = ext2_dir_setattr,

    .lookup = ext2_dir_node_lookup,

    .mkfile = ext2_dir_mkfile,
    .mkdir = ext2_dir_mkdir,
    .unlink = ext2_dir_unlink,

    .mkfifo = fs_node_cannot_mkfifo,
    .link = fs_node_cannot_link,
    .symlink = fs_node_cannot_symlink,
};



struct fs_file_ops
ext2_dir_file_ops = {
    .read = fs_file_paged_read,
    .write = fs_file_paged_write,
    .seek = fs_file_paged_seek,
    .flush = fs_file_paged_flush,

    .dir_next = ext2_dir_next,
    .dir_begin = ext2_dir_begin,
    .dir_readattr = ext2_dir_readattr,
    .dir_readname = ext2_dir_readname,
};
