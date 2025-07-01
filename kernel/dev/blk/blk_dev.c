
#include <kanawha/dev/blk.h>
#include <kanawha/registry.h>

static int
blk_dev_init(struct blk_dev *dev)
{
    return 0;
}

static int
blk_dev_deinit(struct blk_dev *dev)
{
    return 0;
}

DEFINE_REGISTRY(
        blk_dev,
        registry_node,
        blk_dev_init,
        blk_dev_deinit
        );

