
#include <devicetree/devicetree.h>
#include <devicetree/flat.h>
#include <kanawha/kmalloc.h>
#include <kanawha/vmem.h>
#include <kanawha/string.h>
#include <kanawha/printk.h>

// Statically allocate the first device tree struct
static struct device_tree boot_device_tree;

static DECLARE_SPINLOCK(device_tree_list_lock);
static DECLARE_ILIST(device_tree_list);
static size_t device_tree_list_len = 0;

int
devicetree_provide_dtb(
        struct fdt __phys *phys_dtb)
{
    int res;

    // Check the DTB
    struct fdt *fdt = (struct fdt *)__va(phys_dtb);
    res = fdt_check_header(fdt);
    if(res) {
        return res;
    }

    uint32_t fdt_size = fdttoh32(fdt->hdr.totalsize);

    spin_lock(&device_tree_list_lock);

    struct device_tree *tree = NULL;
    if(device_tree_list_len == 0) {
        tree = &boot_device_tree;
    } else {
        spin_unlock(&device_tree_list_lock);
        tree = kmalloc(sizeof(struct device_tree));
        spin_lock(&device_tree_list_lock);
    }

    if(tree == NULL) {
        spin_unlock(&device_tree_list_lock);
        return -ENOMEM;
    }

    memset(tree, 0, sizeof(struct device_tree));
    tree->backing_data = phys_dtb;
    tree->backing_size = fdt_size;

    ilist_push_tail(&device_tree_list, &tree->list_node);
    device_tree_list_len++;

    spin_unlock(&device_tree_list_lock);
    return 0;
}

struct device_tree *
devicetree_get(void) {
    if(device_tree_list_len > 0) {
        return &boot_device_tree;
    }
    return NULL;
}

struct fdt *
devicetree_get_fdt(
        struct device_tree *dt)
{
    return __va(dt->backing_data);
}

static int
init_dump_device_trees(void)
{
    int res;
    spin_lock(&device_tree_list_lock);
    ilist_node_t *node;
    ilist_for_each(node, &device_tree_list) {
        struct device_tree *dt = container_of(node, struct device_tree, list_node);
        struct fdt *fdt = devicetree_get_fdt(dt);
        res = dump_fdt(do_printk, fdt);
        if(res) {
            spin_unlock(&device_tree_list_lock);
            return res;
        }
    }
    spin_unlock(&device_tree_list_lock);
    return 0;
}
declare_init(static, init_dump_device_trees);

