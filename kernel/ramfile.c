
#include <kanawha/fs/type.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/stree.h>
#include <kanawha/stdint.h>
#include <kanawha/stddef.h>
#include <kanawha/vmem.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>
#include <kanawha/init.h>

struct fs_node_ops;

struct ramfile
{
    spinlock_t lock;
    struct stree_fs_node fs_node;

    size_t page_refs;

    paddr_t paddr;
    size_t size;
};

#define RAMFILE_FROM_FS_NODE(fs_node_ptr)\
    ({ (struct ramfile *)container_of(\
            container_of(fs_node_ptr, struct stree_fs_node, fs_node),\
            struct ramfile,\
            fs_node); })

static int
ramfile_read(
        struct fs_node *node,
        void *buffer,
        size_t *amount,
        uintptr_t offset)
{
    struct ramfile *ramfile =
        RAMFILE_FROM_FS_NODE(node);

    spin_lock(&ramfile->lock);

    if(offset >= ramfile->size) {
        spin_unlock(&ramfile->lock);
        return -ERANGE;
    }

    size_t room_left = ramfile->size - offset;
    if(*amount > room_left) {
        *amount = room_left;
    }

    void *data = (void*)__va(ramfile->paddr);
    memmove(buffer, data + offset, *amount);

    spin_unlock(&ramfile->lock);

    return 0;
}

static int
ramfile_write(
        struct fs_node *node,
        void *buffer,
        size_t *amount,
        uintptr_t offset)
{
    struct ramfile *ramfile =
        RAMFILE_FROM_FS_NODE(node);

    spin_lock(&ramfile->lock);

    if(offset >= ramfile->size) {
        spin_unlock(&ramfile->lock);
        return -ERANGE;
    }

    size_t room_left = ramfile->size - offset;
    if(*amount > room_left) {
        *amount = room_left;
    }

    void *data = (void*)__va(ramfile->paddr);
    memmove(data + offset, buffer, *amount);

    spin_unlock(&ramfile->lock);

    return 0;
}

static int
ramfile_flush(
        struct fs_node *node)
{
    // TODO: Flush caches of any CPU(s) which might have written
    // to this ramfile (only needed with a weaker memory model)

    return 0;
}

static int
ramfile_attr(
        struct fs_node *node,
        int attr_index,
        size_t *attr_val)
{
    struct ramfile *ramfile =
        RAMFILE_FROM_FS_NODE(node);

    spin_lock(&ramfile->lock);

    switch(attr_index) {
        case FS_NODE_ATTR_MAX_OFFSET:
            *attr_val = ramfile->size-1;
            break;
        case FS_NODE_ATTR_MAX_OFFSET_END:
            *attr_val = ramfile->size;
            break;
        case FS_NODE_ATTR_CHILD_COUNT:
            *attr_val = 0;
            break;
        default:
            spin_unlock(&ramfile->lock);
            return -EINVAL;
    }

    spin_unlock(&ramfile->lock);

    return 0;
}

struct fs_node_ops 
ramfile_fs_node_ops = {
    .get_child = childless_fs_node_get_child,
    .child_name = childless_fs_node_child_name,

    .read = ramfile_read,
    .write = ramfile_write,
    .flush = ramfile_flush,
    .attr = ramfile_attr,
};

static struct stree_fs_mount __ramfile_mount;

static int
ramfile_mount_init(void)
{
    int res;

    res = stree_fs_mount_init(&__ramfile_mount);
    if(res) {
        return res;
    }

//    res = fs_attach_mount(
//            &__ramfile_mount.mount,
//            "ramfile");
//    if(res) {
//        stree_fs_mount_deinit(&__ramfile_mount);
//        return res;
//    }

    return 0;
}
declare_init_desc(bus, ramfile_mount_init, "Attaching ramfile Mount");

struct fs_mount *
ramfile_mount(void)
{
    return &__ramfile_mount.mount;
}

int
create_ramfile(
        const char *ramfile_name,
        paddr_t paddr,
        size_t size)
{
    int res;

    struct ramfile *ramfile =
        kmalloc(sizeof(struct ramfile));
    if(ramfile == NULL) {
        return -ENOMEM;
    }
    memset(ramfile, 0, sizeof(struct ramfile));

    ramfile->size = size;
    ramfile->paddr = paddr;
    spinlock_init(&ramfile->lock);

    order_t base_order = ptr_orderof(paddr);
    order_t end_order = ptr_orderof(paddr + size);

    ramfile->page_refs = 0;

    ramfile->fs_node.fs_node.ops = &ramfile_fs_node_ops;

    res = stree_fs_mount_insert(
            &__ramfile_mount,
            &ramfile->fs_node,
            ramfile_name);
    if(res) {
        kfree(ramfile);
        return res;
    }

    return 0;
}

int
destroy_ramfile(
        const char *ramfile_name)
{
    return -EUNIMPL;
}

struct fs_node *
ramfile_get(const char *name)
{
    int res; 

    struct fs_mount *mnt = ramfile_mount();
    if(mnt == NULL) {
        return NULL;
    }

    size_t root_index;

    res = fs_mount_root_index(mnt, &root_index);
    if(res) {
        return NULL;
    }

    struct fs_node *root_node =
        fs_mount_get_node(mnt, root_index);

    if(root_node == NULL) {
        return NULL;
    }

    size_t num_children;
    res = fs_node_attr(root_node, FS_NODE_ATTR_CHILD_COUNT, &num_children);
    if(res) {
        fs_node_put(root_node);
        return NULL;
    }

    size_t namelen = strlen(name);
    char buf[namelen+1];

    for(size_t child_index = 0; child_index < num_children; child_index++) {
        res = fs_node_child_name(root_node, child_index, buf, namelen+1);
        if(res) {
            continue;
        }
        buf[namelen] = '\0';

        if(strcmp(buf, name) != 0) {
            continue;
        }

        size_t node_index;
        res = fs_node_get_child(root_node, child_index, &node_index);
        if(res) {
            fs_node_put(root_node);
            return NULL;
        }

        struct fs_node *node;
        node = fs_mount_get_node(mnt, node_index);
        fs_node_put(root_node);
        return node;
    }

    fs_node_put(root_node);
    return NULL;
}

int
ramfile_put(struct fs_node *node)
{
    return fs_node_put(node);
}

