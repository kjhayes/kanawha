
#include <kanawha/ref.h>

int
refobj_init(struct refobj *obj, struct refobj_ops *ops)
{
    obj->ops = ops;
    DEBUG_ASSERT(obj->ops->release != NULL);
    atomic_set_relaxed(&obj->refcount, 1);
    return 0;
}

void
refobj_put(struct refobj *obj)
{
    atomic_val_t val = atomic_fetch_dec(&obj->refcount);
    if(val == 1)
    {
        // Need to release the object (Ideally this should be done in a
        // tasklet)
        DEBUG_ASSERT(obj->ops->release);
        (*obj->ops->release)(obj);
    }
}
void
refobj_get(struct refobj *obj)
{
    atomic_val_t old = atomic_fetch_inc(&obj->refcount);

    // This would be a misuse of the "refobj" framework
    DEBUG_ASSERT(old != 0);
}
