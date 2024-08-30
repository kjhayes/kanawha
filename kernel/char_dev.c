
#include <kanawha/char_dev.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>
#include <kanawha/spinlock.h>
#include <kanawha/stddef.h>
#include <kanawha/fs.h>
#include <kanawha/init.h>
#include <kanawha/assert.h>
#include <kanawha/string.h>

static DECLARE_SPINLOCK(char_dev_tree_lock);
static size_t num_char_dev = 0;
static DECLARE_STREE(char_dev_tree);
static DECLARE_PTREE(char_dev_fs_node_tree);

static struct fs_node_ops char_dev_fs_node_ops;

int
register_char_dev(
        struct char_dev *chr,
        const char *name,
        struct char_driver *driver,
        struct device *device)
{
    spin_lock(&char_dev_tree_lock);

    struct stree_node *existing = stree_get(&char_dev_tree, name);
    if(existing != NULL) {
        spin_unlock(&char_dev_tree_lock);
        return -EEXIST;
    }

    chr->device = device;
    chr->driver = driver;
    dprintk("Registering char_dev \"%s\" name=%p\n", name, name);
    chr->char_dev_node.key = name;

    stree_insert(&char_dev_tree, &chr->char_dev_node);

    // Assign the node a fs_node index
    ptree_insert_any(&char_dev_fs_node_tree, &chr->fs_node.tree_node);
    dprintk("fs_node_index=0x%llx\n", (ull_t)chr->fs_node.tree_node.key);
    DEBUG_ASSERT(chr->fs_node.tree_node.key != 0);

    num_char_dev++;

    spin_unlock(&char_dev_tree_lock);
    return 0;
}

int
unregister_char_dev(struct char_dev *dev)
{
    return -EUNIMPL;
}

struct char_dev *
find_char_dev(const char *name)
{
    spin_lock(&char_dev_tree_lock);
    struct stree_node *node = stree_get(&char_dev_tree, name);
    spin_unlock(&char_dev_tree_lock);
    if(node == NULL) {
        return NULL;
    }
    return container_of(node, struct char_dev, char_dev_node);
}

// Chardev FS Mount

static struct char_dev_fs_mount
{
    struct fs_mount fs_mount;
    struct char_dev_fs_node root_node;
} char_dev_fs_mount = {0};

static int
char_dev_fs_root_node_get_child(
        struct fs_node *node,
        size_t index,
        size_t *node_index)
{
    int res;
    spin_lock(&char_dev_tree_lock);
    if(index < num_char_dev) {
        struct ptree_node *node = ptree_get_first(&char_dev_fs_node_tree);
        // First one should be the root node
        DEBUG_ASSERT(node != NULL);

        node = ptree_get_next(node);
        while(index > 0 && node != NULL) {
            node = ptree_get_next(node);
            index--;
        }
        if(node == NULL) {
            res = -ENXIO;
            goto exit;
        }
        *node_index = node->key;
        res = 0;
    } else {
        res = -ENXIO;
    }
exit:
    spin_unlock(&char_dev_tree_lock);
    return res;
}

static int
char_dev_fs_root_node_child_name(
        struct fs_node *node,
        size_t index,
        char *buf,
        size_t buf_size)
{
    int res;
    spin_lock(&char_dev_tree_lock);
    if(index < num_char_dev) {
        struct ptree_node *node = ptree_get_first(&char_dev_fs_node_tree);
        DEBUG_ASSERT(node != NULL); // Root node

        node = ptree_get_next(node);
        while(index > 0 && node != NULL) {
            node = ptree_get_next(node);
            index--;
        }
        if(node == NULL) {
            res = -ENXIO;
            goto exit;
        }
        struct char_dev_fs_node *fs_node =
            container_of(node, struct char_dev_fs_node, tree_node);
        dprintk("fs_node=%p, fs_node->key=0x%llx\n",
                fs_node, (ull_t)fs_node->tree_node.key);
        struct char_dev *cd = container_of(fs_node, struct char_dev, fs_node);
        const char *name = cd->char_dev_node.key;
        dprintk("char_dev_fs_root_node_child_name: name=%s, name_ptr=%p, buf_size = 0x%llx\n",
                name, name, (ull_t)buf_size);
        strncpy(buf, name, buf_size);
        res = 0;
    }
exit:
    spin_unlock(&char_dev_tree_lock);
    return res;
}

static int
char_dev_fs_root_node_read(
        struct fs_node *node,
        void *buffer,
        size_t *amount,
        size_t offset)
{
    return -EINVAL;
}

static int
char_dev_fs_root_node_write(
        struct fs_node *node,
        void *buffer,
        size_t *amount,
        size_t offset)
{
    return -EINVAL;
}

static int
char_dev_fs_root_node_flush(
        struct fs_node *node)
{
    return 0;
}

static int
char_dev_fs_root_node_attr(
        struct fs_node *fs_node,
        int attr_index,
        size_t *out)
{
    struct char_dev_fs_node *node =
        container_of(fs_node, struct char_dev_fs_node, fs_node);

    switch(attr_index) {
        case FS_NODE_ATTR_MAX_OFFSET:
        case FS_NODE_ATTR_MAX_OFFSET_END:
            *out = 0;
            break;
        case FS_NODE_ATTR_CHILD_COUNT:
            *out = num_char_dev;
            break;
        default:
            return -EINVAL;
    }

    return 0;
}

static int
char_dev_fs_node_get_child(
        struct fs_node *node,
        size_t index,
        size_t *node_index)
{
    return -EINVAL;
}

static int
char_dev_fs_node_child_name(
        struct fs_node *node,
        size_t index,
        char *buf,
        size_t buf_size)
{
    return -EINVAL;
}

static int
char_dev_fs_node_read(
        struct fs_node *node,
        void *buffer,
        size_t *amount,
        size_t offset)
{
    struct char_dev_fs_node *cd_node =
        container_of(node, struct char_dev_fs_node, fs_node);
    struct char_dev *dev = container_of(cd_node, struct char_dev, fs_node);

    if(offset != 0) {
        return -EINVAL;
    }

    *amount = char_dev_read(dev, buffer, *amount);

    return 0;
}

static int
char_dev_fs_node_write(
        struct fs_node *node,
        void *buffer,
        size_t *amount,
        size_t offset)
{
    struct char_dev_fs_node *cd_node =
        container_of(node, struct char_dev_fs_node, fs_node);
    struct char_dev *dev = container_of(cd_node, struct char_dev, fs_node);

    if(offset != 0) {
        return -EINVAL;
    }

    *amount = char_dev_write(dev, buffer, *amount);

    return 0;
}

static int
char_dev_fs_node_flush(
        struct fs_node *node)
{
    struct char_dev_fs_node *cd_node =
        container_of(node, struct char_dev_fs_node, fs_node);
    struct char_dev *dev = container_of(cd_node, struct char_dev, fs_node);

    return char_dev_flush(dev);
}

static int
char_dev_fs_node_attr(
        struct fs_node *fs_node,
        int attr_index,
        size_t *out)
{
    struct char_dev_fs_node *node =
        container_of(fs_node, struct char_dev_fs_node, fs_node);

    switch(attr_index) {
        case FS_NODE_ATTR_MAX_OFFSET:
        case FS_NODE_ATTR_MAX_OFFSET_END:
            *out = 0;
            break;
        case FS_NODE_ATTR_CHILD_COUNT:
            *out = 0;
            break;
        default:
            return -EINVAL;
    }

    return 0;
}

static int
char_dev_fs_mount_root_index(
        struct fs_mount *mnt,
        size_t *index)
{
    *index = 0;
    return 0;
}

static struct fs_node *
char_dev_fs_mount_load_node(
        struct fs_mount *mnt,
        size_t index)
{
    struct char_dev_fs_mount *cd_mnt =
        container_of(mnt, struct char_dev_fs_mount, fs_mount);

    if(index == 0) {
        return &cd_mnt->root_node.fs_node;
    }

    spin_lock(&char_dev_tree_lock);

    struct ptree_node *tree_node =
        ptree_get(&char_dev_fs_node_tree, index);
    if(tree_node == NULL) {
        spin_unlock(&char_dev_tree_lock);
        return NULL;
    }

    struct char_dev_fs_node *cd_node =
        container_of(tree_node, struct char_dev_fs_node, tree_node);

    cd_node->fs_node.ops = &char_dev_fs_node_ops;

    spin_unlock(&char_dev_tree_lock);
    return &cd_node->fs_node;
}

static int
char_dev_fs_mount_unload_node(
        struct fs_mount *mnt,
        struct fs_node *node)
{
    struct char_dev_fs_mount *cd_mnt =
        container_of(mnt, struct char_dev_fs_mount, fs_mount);
    struct char_dev_fs_node *cd_node =
        container_of(node, struct char_dev_fs_node, fs_node);

    if(node == &cd_mnt->root_node.fs_node) {
        return 0;
    }

    return 0;
}

static struct fs_node_ops
char_dev_fs_root_node_ops = {
    .get_child = char_dev_fs_root_node_get_child, 
    .child_name = char_dev_fs_root_node_child_name, 
    .flush = char_dev_fs_root_node_flush,
    .read = char_dev_fs_root_node_read,
    .write = char_dev_fs_root_node_write,
    .attr = char_dev_fs_root_node_attr,
};

static struct fs_node_ops
char_dev_fs_node_ops = {
    .get_child = char_dev_fs_node_get_child, 
    .child_name = char_dev_fs_node_child_name, 
    .flush = char_dev_fs_node_flush,
    .read = char_dev_fs_node_read,
    .write = char_dev_fs_node_write,
    .attr = char_dev_fs_node_attr,
};

static struct fs_mount_ops
char_dev_fs_mount_ops = {
    .load_node = char_dev_fs_mount_load_node,
    .unload_node = char_dev_fs_mount_unload_node,
    .root_index = char_dev_fs_mount_root_index,
};

static int
char_dev_init_fs_mount(void)
{
    int res;
    struct char_dev_fs_mount *cd_mnt = &char_dev_fs_mount;
    cd_mnt->root_node.fs_node.mount = &cd_mnt->fs_mount;
    cd_mnt->root_node.fs_node.ops = &char_dev_fs_root_node_ops;
    res = init_fs_mount_struct(&cd_mnt->fs_mount, &char_dev_fs_mount_ops);
    if(res) {
        eprintk("Failed to initialize chardev fs mount struct! (err=%s)\n",
                errnostr(res));
        return res;
    }

    res = fs_attach_mount(&cd_mnt->fs_mount, "char");
    if(res) {
        eprintk("Failed to attach chardev fs mount (\"char\")! (err=%s)\n",
                errnostr(res));
        return res;
    }

    return 0;
}
declare_init(fs, char_dev_init_fs_mount);

static int
char_dev_init_static(void)
{
    // Make sure we insert this fs_node early enough that no char_dev 
    // gets assigned to node_index 0
    return ptree_insert(&char_dev_fs_node_tree, &char_dev_fs_mount.root_node.tree_node, 0);
}
declare_init(static, char_dev_init_static);

struct fs_mount *
char_dev_get_mount(void)
{
    return &char_dev_fs_mount.fs_mount;
}

