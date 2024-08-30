
#include <kanawha/device.h>
#include <kanawha/init.h>
#include <kanawha/string.h>
#include <kanawha/errno.h>
#include <kanawha/stddef.h>
#include <kanawha/export.h>

static DECLARE_ILIST(root_device_list);
static DECLARE_ILIST(global_device_list);

int
register_device(
        struct device *dev,
        struct device_ops *ops,
        struct device *parent)
{
    memset(dev, 0, sizeof(struct device));

    dev->ops = ops;
    dev->parent = parent;
    dev->num_children = 0;

    ilist_init(&dev->children);

    if(dev->parent) {
        ilist_push_tail(&dev->parent->children, &dev->parent_node);
        dev->parent->num_children++;
    } else {
        ilist_push_tail(&root_device_list, &dev->parent_node);
    }
    ilist_push_tail(&global_device_list, &dev->global_node);

#define MAX_NAMELEN 64
    char name_buf[MAX_NAMELEN + 1];
    name_buf[MAX_NAMELEN] = '\0';

    int res = device_read_name(dev, name_buf, MAX_NAMELEN);
    if(res) {
        eprintk("Registered device but failed to read it's name!\n");
    } else {
        printk("Registered Device \"%s\"\n", name_buf);
    }
#undef MAX_NAMELEN

    return 0;
}

int
unregister_device(struct device *dev)
{
    if(dev->num_children > 0) {
        return -EINVAL;
    }

    if(dev->parent) {
        dev->parent->num_children--;
        ilist_remove(&dev->parent->children, &dev->parent_node);
    } else {
        ilist_remove(&root_device_list, &dev->parent_node);
    }

    ilist_remove(&global_device_list, &dev->global_node);
    return 0;
}

EXPORT_SYMBOL(register_device);
EXPORT_SYMBOL(unregister_device);

int dump_devices(printk_f *printer) {

#define MAX_DEV_NAMELEN 64
    char name_buf[MAX_DEV_NAMELEN+1];
    name_buf[MAX_DEV_NAMELEN] = '\0';

    ilist_node_t *node;
    ilist_for_each(node, &global_device_list) {
        struct device *dev = container_of(node, struct device, global_node);
        int res = device_read_name(dev, name_buf, MAX_DEV_NAMELEN);
        if(res == 0) {
            (*printer)("Device \"%s\"\n", name_buf);
        } else {
            (*printer)("Device \"ERROR-UNKNOWN\"\n");
        }
    }
    return 0;

#undef MAX_DEV_NAMELEN
}

static inline void
print_indent_up_to(printk_f *printer, int depth) {
    for(int i = 0; i < depth; i++) {
        (*printer)("\t");
    }
}

static inline void
dump_device_subtree(printk_f *printer, struct device *dev, int depth)
{
#define MAX_DEV_NAMELEN 64
    char name_buf[MAX_DEV_NAMELEN+1];
    name_buf[MAX_DEV_NAMELEN] = '\0';

    print_indent_up_to(printer, depth);

    int res = device_read_name(dev, name_buf, MAX_DEV_NAMELEN);
    if(res == 0) {
        (*printer)("[%s]", name_buf);
    } else {
        (*printer)("[ERROR-UNKNOWN]"); 
    }
    if(dev->num_children) {
        print_indent_up_to(printer, depth);
        (*printer)(" {\n");
        ilist_node_t *node;
        ilist_for_each(node, &dev->children) {
            struct device *child = container_of(node, struct device, parent_node);
            dump_device_subtree(printer, child, depth+1);
        }
        print_indent_up_to(printer, depth);
        (*printer)("}");
    }
    (*printer)(",\n");
#undef MAX_DEV_NAMELEN
}

int dump_device_hierarchy(printk_f *printer)
{
    ilist_node_t *root_node;
    ilist_for_each(root_node, &root_device_list) {
        struct device *root_dev = container_of(root_node, struct device, parent_node);
        dump_device_subtree(printer, root_dev, 0);
    }
    return 0;
}

