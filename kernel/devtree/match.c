
#include <devtree/match.h>
#include <devtree/driver.h>
#include <devtree/devtree.h>
#include <devtree/flat.h>
#include <kanawha/list.h>
#include <kanawha/spinlock.h>
#include <kanawha/string.h>

// Driver/Node Matching
static DECLARE_SPINLOCK(devtree_match_lock);
static DECLARE_ILIST(dt_driver_list);
static DECLARE_ILIST(devtree_node_list);
#define MATCH_LOCK()\
    do {\
        spin_lock(&devtree_match_lock);\
    } while(0)
#define MATCH_UNLOCK()\
    do {\
        spin_unlock(&devtree_match_lock);\
    } while(0)

// Returns 0 if the id matches the node
int
dt_node_check_id(
        struct dt_node *node,
        struct dt_node_id *id)
{
    struct fdt *fdt = devtree_get_fdt(node->dt);

    DEBUG_ASSERT(id->name != NULL || id->type != NULL || id->compatible != NULL);
    if(id->name != NULL) {
        char *unitname = fdt_node_unitname(fdt, node->backing_data);
        if(strcmp(unitname, id->name)) {
            return -EINVAL;
        }
    }

    if(id->type != NULL) {
        struct fdt_property *device_type =
            fdt_find_property_by_name(fdt, node->backing_data, "device_type");
        if(device_type == NULL) {
            return -EINVAL;
        }
        if(strcmp(fdt_property_data(fdt, device_type), id->type)) {
            return -EINVAL;
        }
    }

    if(id->compatible) {
        struct fdt_property *compatible =
            fdt_find_property_by_name(fdt, node->backing_data, "compatible");
        if(compatible == NULL) {
            return -EINVAL;
        }

        int found_compatible = 0;

        ssize_t size = fdt_property_size(fdt, compatible);
        char *data = fdt_property_data(fdt, compatible);
        while(size > 0) {
            char *str = data;
            size_t str_len = strlen(str);

            data += str_len+1;
            size -= str_len+1;
            DEBUG_ASSERT(size >= 0);

            if(strcmp(str, id->compatible) == 0) {
                found_compatible = 1;
                break;
            }
        }

        if(!found_compatible) {
            return -EINVAL;
        }
    }

    return 0;
}

static int
devtree_try_match(
        struct dt_driver *driver,
        struct dt_node *node)
{
    int res;
    int matched_id = 0;
    for(size_t i = 0; i < driver->num_ids; i++) {
        struct dt_node_id *id = &driver->ids[i];
        if(dt_node_check_id(node, id) == 0) {
            matched_id = 1;
            break;
        }
    }

    if(!matched_id) {
        return -EINVAL;
    }

    res = dt_driver_probe(
            driver,
            node);
    if(res) {
        return res;
    }

    res = dt_driver_init_node(
            driver,
            node);
    if(res) {
        return res;
    }

    node->driver = driver;
    ilist_push_tail(&driver->devices, &node->driver_node);

    return 0;
}

static int
__init_dt_driver(
        struct dt_driver *driver)
{
    ilist_init(&driver->devices);
    return 0;
}

int
register_dt_driver(
        struct dt_driver *driver)
{
    int res;

    res = __init_dt_driver(driver);
    if(res) {
        return res;
    }

    MATCH_LOCK();

    ilist_push_tail(&dt_driver_list, &driver->global_node);

    ilist_node_t *list_node;
    ilist_for_each(list_node, &devtree_node_list) {
        struct dt_node *node =
            container_of(list_node, struct dt_node, global_node);
        if(node->flags & DT_NODE_FLAG_MATCHED) {
            continue;
        }
        int res = devtree_try_match(
                driver,
                node);
        if(res) {
            // We don't actually care if we fail to match with any given node
            continue;
        }
        node->flags |= DT_NODE_FLAG_MATCHED;
    }

    MATCH_UNLOCK();

    return 0;
}

int
register_dt_driver_nomatch(
        struct dt_driver *driver)
{
    int res;
    res = __init_dt_driver(driver);
    if(res) {
        return res;
    }
    return 0;
}

static int
register_dt_node(
        struct dt_node *node)
{
    int res;

    MATCH_LOCK();
    ilist_push_tail(&devtree_node_list, &node->global_node);

    ilist_node_t *list_node;
    ilist_for_each(list_node, &dt_driver_list) {
        struct dt_driver *driver =
            container_of(list_node, struct dt_driver, global_node);
        int res = devtree_try_match(
                driver,
                node);
        if(res == 0) {
            node->flags |= DT_NODE_FLAG_MATCHED;
            break;
        }
    }

    MATCH_UNLOCK();
    return 0;
}

static int
register_dt_node_and_children(
        struct dt_node *node)
{
    int res;
    res = register_dt_node(node);
    if(res) {
        return res;
    }

    ilist_node_t *list_node;
    ilist_for_each(list_node, &node->children) {
        struct dt_node *child =
            container_of(list_node, struct dt_node, child_node);
        res = register_dt_node_and_children(child);
        if(res) {
            return res;
        }
    }

    return 0;
}

int
register_devtree(struct devtree *dt)
{
    return register_dt_node_and_children(dt->root_node);
}

int
dt_driver_claim_node(
        struct dt_driver *driver,
        struct dt_node *node)
{
    int res;

    if((node->flags & DT_NODE_FLAG_MATCHED) || node->driver) {
        MATCH_UNLOCK();
        return -EALREADY;
    }
    node->driver = driver;
    ilist_push_tail(&driver->devices, &node->driver_node);

    node->flags |= DT_NODE_FLAG_MATCHED;

    return 0;
}

