// CPIO Archive as a Filesystem

#include <kanawha/fs.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/vmem.h>
#include <kanawha/stddef.h>

#define CPIO_FS_TYPE_NAME "cpio"
#define CPIO_ROOT_INDEX 0x10000

static struct fs_node_ops cpio_fs_node_ops;
static struct fs_mount_ops cpio_fs_mount_ops;

typedef enum {
    CPIO_ASCII,
    CPIO_BINARY,
} cpio_type_t;

#define CPIO_HEADER_MAGIC 0x71c7

struct cpio_binary_header {
    uint16_t c_magic;
    uint16_t c_dev;
    uint16_t c_ino;
    uint16_t c_mode;
    uint16_t c_uid;
    uint16_t c_gid;
    uint16_t c_nlink;
    uint16_t c_rdev;
    uint16_t c_mtime[2];
    uint16_t c_namesize;
    uint16_t c_filesize[2];
} __attribute__((packed));

struct cpio_header {
    struct cpio_binary_header binary;
};

struct cpio_node
{
    struct fs_node fs_node;

    int is_root;

    // Non-Root Only
    struct cpio_header hdr;
    size_t header_offset;
    size_t data_offset;

    struct cpio_index *index;

    struct cpio_mount *mnt;
};

struct cpio_mount
{
    struct fs_mount mnt;

    cpio_type_t type;
    struct fs_node *backing_file;

    struct cpio_node root_node;

    size_t num_files;
    struct ptree index_tree;
    size_t *index_to_ino;
};

// Very small data structure to
// avoid scanning the entire block
// device on every fs_node load
//
// This will live as long as the cpio_mount
struct cpio_index {
    struct ptree_node node;
    size_t offset;
    size_t filesize;
    const char *name;
};

static int
cpio_copy_node_header(struct cpio_mount *mnt, size_t offset, struct cpio_header *hdr)
{
    int res;
    size_t size;
    switch(mnt->type) {
      case CPIO_BINARY:
        size = sizeof(struct cpio_binary_header);
        res = fs_node_read(
            mnt->backing_file,
            hdr,
            &size,
            offset);
        break;
      case CPIO_ASCII:
        res = -EUNIMPL;
        break;
      default:
        res = -EINVAL;
        break;
    }
    return res;
}


static struct fs_node *
cpio_mount_load_node(
        struct fs_mount *fs_mnt,
        size_t node_index)
{
    int res;

    struct cpio_mount *mnt = container_of(fs_mnt, struct cpio_mount, mnt);

    if(node_index == CPIO_ROOT_INDEX) {
        return &mnt->root_node.fs_node;
    }

    struct ptree_node *pnode;
    pnode = ptree_get(&mnt->index_tree, node_index);
    if(pnode == NULL) {
        return NULL;
    }
    struct cpio_index *index = container_of(pnode, struct cpio_index, node);

    struct cpio_node *node = kmalloc(sizeof(struct cpio_node));
    if(node == NULL) {
        return NULL;
    }

    node->header_offset = index->offset;
    node->is_root = 0;
    node->index = index;
    node->mnt = mnt;
    node->fs_node.ops = &cpio_fs_node_ops;

    res = cpio_copy_node_header(node->mnt, node->header_offset, &node->hdr);
    if(res) {
        kfree(node);
        return NULL;
    }

    node->data_offset =
        node->header_offset
        + sizeof(struct cpio_binary_header)
        + ((node->hdr.binary.c_namesize + 1) & ~1);

    return &node->fs_node;
}

static int
cpio_mount_unload_node(
        struct fs_mount *mnt,
        struct fs_node *fs_node)
{
    struct cpio_node *node =
        container_of(fs_node, struct cpio_node, fs_node);

    if(!node->is_root) {
      kfree(node);
    }
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
        struct fs_type *bfs,
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
            &mnt->mnt,
            &cpio_fs_mount_ops);
    if(res) {goto err0;}


    res = fs_node_get_again(backing_node);
    if(res) {
        goto err0;
    }

    mnt->backing_file = backing_node;

    mnt->type = CPIO_BINARY; // For now, this is all we will support

    mnt->root_node.is_root = 1;
    mnt->root_node.mnt = mnt;
    mnt->root_node.fs_node.ops = &cpio_fs_node_ops;
    
    ptree_init(&mnt->index_tree);

    size_t file_size;
    res = fs_node_attr(
            mnt->backing_file,
            FS_NODE_ATTR_MAX_OFFSET_END,
            &file_size);
    if(res) {
        goto err1;
    }

    struct cpio_header hdr;
    size_t offset = 0;

    size_t num_nodes = 0;
    int found_terminator = 0;

    do {
        res = cpio_copy_node_header(mnt, offset, &hdr);
        if(res) {
            break;
        }
        if(hdr.binary.c_magic != CPIO_HEADER_MAGIC) {
            eprintk("Found file in CPIO filesystem with invalid magic! (file=0x%x, magic=0x%x)\n", hdr.binary.c_magic, CPIO_HEADER_MAGIC);
            // If this isn't our first iteration, we might be leaking memory
            goto err1;
        }

        size_t namesize = hdr.binary.c_namesize;
        dprintk("namesize=0x%x hdrsize=%d\n", namesize, sizeof(struct cpio_binary_header));
        char name_buf[namesize + 1];

        if(offset + sizeof(struct cpio_binary_header) + namesize > file_size) {
            res = -ERANGE;
        } else {
            res = fs_node_read(
                mnt->backing_file,
                name_buf,
                &namesize,
                offset + sizeof(struct cpio_binary_header));
        }
        if(res) {
            eprintk("Failed to read CPIO file name! (err=%s)\n",
                    errnostr(res));
            continue;
        }
        name_buf[namesize] = '\0';

        if(strcmp(name_buf, "TRAILER!!!") == 0) {
            // This is our terminator
            found_terminator = 1;
            break;
        }

        size_t filesize = hdr.binary.c_filesize[1] + ((size_t)hdr.binary.c_filesize[0]<<16);

        struct cpio_index *index = kmalloc(sizeof(struct cpio_index));
        if(index == NULL) {
            res = -ENOMEM;
            goto err1;
        }
        index->offset = offset;
        index->filesize = filesize;
        index->name = kstrdup(name_buf);
        if(index->name == NULL) {
            eprintk("Failed to copy CPIO file name\n");
            kfree(index);
            continue;
        }

        index->node.key = hdr.binary.c_ino;
        res = ptree_insert(&mnt->index_tree, &index->node, hdr.binary.c_ino);
        if(res) {
            kfree(index);
            eprintk("Found duplicate inode 0x%x in CPIO filesystem! (ignoring fow now...)\n", hdr.binary.c_ino);
            continue;
        }
        num_nodes++;     
        // Try and go to the next file
        offset += sizeof(struct cpio_binary_header);
        offset += (namesize + 1) & ~1;
        offset += (filesize + 1) & ~1;

        dprintk("Found File: \"%s\" in CPIO Filesystem file_size=0x%x, namesize=0x%x\n", name_buf, hdr.binary.c_filesize, hdr.binary.c_namesize);

        // This bounds check is imperfect
    } while(offset + sizeof(struct cpio_header) < file_size);

    if(!found_terminator) {
        eprintk("Warning: Ran into end of Disk before CPIO terminator file!\n");
    }

    mnt->num_files = num_nodes;

    mnt->index_to_ino = kmalloc(sizeof(size_t) * mnt->num_files);
    if(mnt->index_to_ino == NULL) {
        res = -ENOMEM;
        goto err1;
    }

    // Set up mapping from root directory index to inode number
    size_t i = 0;
    struct ptree_node *iter = ptree_get_first(&mnt->index_tree);
    while(iter != NULL && i < mnt->num_files)
    {
        dprintk("CPIO map %ld -> 0x%lx\n",
                i, iter->key);
        mnt->index_to_ino[i] = iter->key;
        iter = ptree_get_next(iter);
        i++;
    }

    dprintk("Initialized CPIO Filesystem Mount with %ld File(s)\n", (long)num_nodes);
    
    *out_ptr = &mnt->mnt;
    return 0;

err1:
    fs_mount_put_node(mnt->backing_file->mount, mnt->backing_file);
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

static int
cpio_node_child_name(
        struct fs_node *fs_node,
        size_t index,
        char *buf,
        size_t bufsize)
{
    struct cpio_node *node =
        container_of(fs_node, struct cpio_node, fs_node);

    if(index >= node->mnt->num_files) {
        eprintk("CPIO: cpio_node_child_name with index >= mnt->num_files!\n");
        return -ENXIO;
    }

    size_t ino = node->mnt->index_to_ino[index];

    if(node->is_root) {
        struct ptree_node *pnode = ptree_get(&node->mnt->index_tree, ino);
        if(pnode == NULL) {
            eprintk("CPIO cpio_node_child_name, failed to find ino=0x%lx, index=%ld ptree_node!\n",
                    ino, index);
            pnode = ptree_get_first(&node->mnt->index_tree);
            while(pnode != NULL) {
                eprintk("INO: 0x%lx\n", pnode->key);
                pnode = ptree_get_next(pnode);
            }
            return -ENXIO;
        }
        struct cpio_index *index =
            container_of(pnode, struct cpio_index, node);
        dprintk("CPIO child_name: %s\n", index->name);
        strncpy(buf, index->name, bufsize);
        return 0;
    } else {
        eprintk("CPIO: cpio_node_child_name on non-root node!\n");
        return -EINVAL;
    }
}

static int
cpio_node_get_child(
        struct fs_node *fs_node,
        size_t index,
        size_t *out)
{
    struct cpio_node *node =
        container_of(fs_node, struct cpio_node, fs_node);

    if(index >= node->mnt->num_files) {
        return -ENXIO;
    }

    size_t ino = node->mnt->index_to_ino[index];

    if(node->is_root) {
        *out = ino;
        return 0;
    } else {
        return -EINVAL;
    }
}

static int
cpio_node_flush(
        struct fs_node *fs_node)
{
    // CPIO Filesystem is read-only
    return 0;
}

static int
cpio_node_write(
        struct fs_node *fs_node,
        void *buf,
        size_t *amt,
        size_t offset)
{
    // CPIO filesystem is read-only
    *amt = 0;
    return -EINVAL;
}

static int
cpio_node_read(
        struct fs_node *fs_node,
        void *buf,
        size_t *amt,
        size_t offset)
{
    struct cpio_node *node =
        container_of(fs_node, struct cpio_node, fs_node);

    if(node->is_root) {
        *amt = 0;
        return -EINVAL;
    }

    struct cpio_index *index = node->index;

    // Trim so we don't read off the end of the file
    if(offset + *amt > index->filesize) {
        *amt = index->filesize - offset;
    }

    return fs_node_read(
            node->mnt->backing_file,
            buf,
            amt,
            node->data_offset + offset);
}

static int
cpio_node_attr(
        struct fs_node *fs_node,
        int attr_index,
        size_t *out)
{
    struct cpio_node *node =
        container_of(fs_node, struct cpio_node, fs_node);
    if(node->is_root) {
        switch(attr_index) {
            case FS_NODE_ATTR_MAX_OFFSET:
            case FS_NODE_ATTR_MAX_OFFSET_END:
                *out = 0;
                break;
            case FS_NODE_ATTR_CHILD_COUNT:
                *out = node->mnt->num_files;
                break;
            default:
                return -EINVAL;
        }
        return 0;
    }

    switch(attr_index) {
        case FS_NODE_ATTR_MAX_OFFSET:
            *out = node->index->filesize-1;
            break;
        case FS_NODE_ATTR_MAX_OFFSET_END:
            *out = node->index->filesize;
            break;
        case FS_NODE_ATTR_CHILD_COUNT:
            *out = 0;
            break;
        default:
            return -EINVAL;
    }

    return 0;
}

static struct fs_node_ops
cpio_fs_node_ops = {
    .child_name = cpio_node_child_name,
    .get_child = cpio_node_get_child,
    .flush = cpio_node_flush,
    .read = cpio_node_read,
    .write = cpio_node_write,
    .attr = cpio_node_attr,
};

static struct fs_mount_ops
cpio_fs_mount_ops = {
    .load_node = cpio_mount_load_node,
    .unload_node = cpio_mount_unload_node,
    .root_index = cpio_mount_root_index,
};

static struct fs_type
cpio_fs_type = {
    .mount_file = cpio_mount_file,
    .unmount = cpio_unmount,
};

static int
cpio_register(void) {
    return register_fs_type(&cpio_fs_type, CPIO_FS_TYPE_NAME);
}

declare_init_desc(fs, cpio_register, "Registering CPIO Archive Filesystem");

