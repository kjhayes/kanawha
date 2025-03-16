#ifndef __KANAWHA__DEVTREE_MATCH_H__
#define __KANAWHA__DEVTREE_MATCH_H__

struct devtree;
struct dt_node;
struct dt_driver;

struct dt_node_id {
    // At least one of these must be non-NULL
    char *name; // If NULL will be ignored
    char *type; // If NULL will be ignored
    char *compatible; // If NULL will be ignored
};

// Returns 0 if the id matches the node
int
dt_node_check_id(
        struct dt_node *node,
        struct dt_node_id *id);

int
register_devtree(
        struct devtree *tree);

// Register a driver which will automatically be matched to 
// nodes which match the driver's provided dt_node_id list.
int
register_dt_driver(
        struct dt_driver *driver);

// Register a dt_driver which does not automatically get matched to
// nodes, and must be assigned nodes using dt_driver_claim_node
int
register_dt_driver_nomatch(
        struct dt_driver *driver);

// Claim a node even if the driver does not automatically match the node
// (Useful for claiming subnodes of the driver's root device node)
int
dt_driver_claim_node(
        struct dt_driver *driver,
        struct dt_node *node);

#endif
