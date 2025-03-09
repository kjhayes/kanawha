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

int
register_devtree(
        struct devtree *tree);

int
register_dt_driver(
        struct dt_driver *driver);

#endif
