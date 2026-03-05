
#include <devtree/devtree.h>
#include <devtree/flat.h>
#include <devtree/match.h>
#include <kanawha/kmalloc.h>
#include <kanawha/lock.h>
#include <kanawha/mem_flags.h>
#include <kanawha/printk.h>
#include <kanawha/string.h>
#include <kanawha/vmem.h>

// Statically allocate the first device tree struct
static struct devtree boot_device_tree;

DEFINE_LOCAL_THREAD_LOCK(device_tree_list_lock);
static DECLARE_ILIST(device_tree_list);
static size_t device_tree_list_len = 0;
static int unflatten_device_trees_on_insertion = 0;

// Forward Decl
static int
unflatten_device_tree(struct devtree *tree);
//

int
devtree_provide_fdt(struct fdt *fdt)
{
    int res;

    // Check the DTB
    res = fdt_check_header(fdt);
    if(res)
    {
        return res;
    }

    uint32_t fdt_size = fdttoh32(fdt->hdr.totalsize);

    device_tree_list_lock_acquire();

    struct devtree *tree = NULL;
    if(device_tree_list_len == 0)
    {
        tree = &boot_device_tree;
    }
    else
    {
        device_tree_list_lock_release();
        tree = kmalloc(sizeof(struct devtree), KM_KERNEL);
        device_tree_list_lock_acquire();
    }

    if(tree == NULL)
    {
        device_tree_list_lock_release();
        return -ENOMEM;
    }

    memset(tree, 0, sizeof(struct devtree));
    tree->flags = 0x0;
    tree->root_node = NULL;
    tree->backing_data = fdt;
    tree->backing_size = fdt_size;
    ptree_init(&tree->phandle_tree);

    if(unflatten_device_trees_on_insertion)
    {
        res = unflatten_device_tree(tree);
        if(res)
        {
            if(tree != &boot_device_tree)
            {
                kfree(tree);
            }
            device_tree_list_lock_release();
            return res;
        }
    }

    ilist_push_tail(&device_tree_list, &tree->list_node);
    device_tree_list_len++;

    device_tree_list_lock_release();
    return 0;
}

struct devtree *
devtree_get(void)
{
    if(device_tree_list_len > 0)
    {
        return &boot_device_tree;
    }
    return NULL;
}

struct fdt *
devtree_get_fdt(struct devtree *dt)
{
    return dt->backing_data;
}

static inline struct dt_node *
alloc_dt_node_struct(void)
{
    struct dt_node *node;
    node = kmalloc(sizeof(struct dt_node), KM_KERNEL);
    if(node == NULL)
    {
        return NULL;
    }
    memset(node, 0, sizeof(struct dt_node));

    spinlock_init(&node->name_lock);
    node->name = NULL;

    return node;
}

__maybe_unused static inline void
free_dt_node_struct(struct dt_node *node)
{
    spin_lock(&node->name_lock);
    if(node->name)
    {
        kfree(node->name);
    }
    kfree(node);
}

static struct dt_node *
unflatten_dt_node(struct devtree *dt, struct fdt_node *fdt_node)
{
    struct fdt *fdt = devtree_get_fdt(dt);

    struct dt_node *node = alloc_dt_node_struct();
    if(node == NULL)
    {
        return NULL;
    }

    ilist_init(&node->children);
    node->backing_data = fdt_node;
    node->dt = dt;

    { // Check for a "phandle" property
        struct fdt_property *phandle_prop =
            fdt_find_property_by_name(fdt, fdt_node, "phandle");
        if(phandle_prop != NULL)
        {
            DEBUG_ASSERT(fdt_property_size(fdt, phandle_prop) == 4);
            fdt_phandle_t phandle =
                *(fdt_phandle_t *)fdt_property_data(fdt, phandle_prop);
            ptree_insert(&dt->phandle_tree, &node->phandle_node, phandle);
        }
    }

    int res = 0;

    struct fdt_node *child_fdt_node;
    child_fdt_node = fdt_node_first_subnode(fdt, fdt_node);
    while(child_fdt_node)
    {
        struct dt_node *child = unflatten_dt_node(dt, child_fdt_node);
        if(child == NULL)
        {
            // TODO we don't clean up our children properly on error
            wprintk("Failed to unflatten device tree node! (Could be "
                    "leaking "
                    "memory!)\n");
            break;
        }

        child->parent = node;
        ilist_push_tail(&node->children, &child->child_node);

        child_fdt_node = fdt_node_next_subnode(fdt, child_fdt_node);
    }

    return node;
}

static int
unflatten_device_tree(struct devtree *tree)
{
    int res;

    struct fdt *fdt = devtree_get_fdt(tree);
    struct fdt_node *root = fdt_first_node(fdt);

    DEBUG_ASSERT_MSG(fdt_node_next_subnode(fdt, root) == NULL,
                     "FDT has more than one root node!");

    tree->root_node = unflatten_dt_node(tree, root);

    if(tree->root_node == NULL)
    {
        return -EINVAL;
    }

    tree->root_node->parent = NULL;

    tree->flags |= DEVTREE_FLAG_UNFLATTENED;

    // Register all of the nodes in the tree
    res = register_devtree(tree);
    if(res)
    {
        wprintk("Failed to register device tree nodes! (May only be partially "
                "registered) (err=%s)\n",
                errnostr(res));
    }

    return 0;
}

struct dt_node *
devtree_get_node_by_phandle(struct devtree *dt, fdt_phandle_t phandle)
{
    DEBUG_ASSERT(dt->flags & DEVTREE_FLAG_UNFLATTENED);

    struct ptree_node *pnode = ptree_get(&dt->phandle_tree, phandle);
    if(pnode == NULL)
    {
        return NULL;
    }

    return container_of(pnode, struct dt_node, phandle_node);
}

static int
init_dump_device_trees(void)
{
    int res;
    device_tree_list_lock_acquire();
    ilist_node_t *node;
    ilist_for_each(node, &device_tree_list)
    {
        struct devtree *dt = container_of(node, struct devtree, list_node);
        struct fdt *fdt = devtree_get_fdt(dt);
        res = dump_fdt(do_printk, fdt);
        if(res)
        {
            device_tree_list_lock_release();
            return res;
        }
    }
    device_tree_list_lock_release();
    return 0;
}
declare_init(static, init_dump_device_trees);

static int
unflatten_device_trees(void)
{
    int res;
    device_tree_list_lock_acquire();

    ilist_node_t *node;
    ilist_for_each(node, &device_tree_list)
    {
        struct devtree *dt = container_of(node, struct devtree, list_node);
        res = unflatten_device_tree(dt);
        if(res)
        {
            device_tree_list_lock_release();
            return res;
        }
    }
    unflatten_device_trees_on_insertion = 1;

    device_tree_list_lock_release();
    return 0;
}
declare_init_desc(dynamic,
                  unflatten_device_trees,
                  "Unflattening Device Tree(s)");
