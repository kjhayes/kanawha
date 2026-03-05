#ifndef __KANAWHA__ID_H__
#define __KANAWHA__ID_H__

#include <kanawha/lock.h>

struct id_range
{
    irq_lock_t lock;
    size_t next_avail;
};

#define DEFINE_LOCAL_ID_RANGE(__RANGE, __INITIAL)                              \
    static struct id_range __RANGE;                                            \
    static int __RANGE##_static_init(void)                                     \
    {                                                                          \
        return id_range_init(&__RANGE, __INITIAL);                             \
    }                                                                          \
    declare_init(static, __RANGE##_static_init);

static inline int
id_range_init(struct id_range *range, size_t initial)
{
    irq_lock_init(&range->lock);
    range->next_avail = initial;
    return 0;
}

static inline ssize_t
id_range_alloc(struct id_range *range)
{
    size_t id;
    irq_lock_acquire(&range->lock);
    id = range->next_avail;
    range->next_avail++;
    irq_lock_release(&range->lock);
    return id;
}

static inline int
id_range_free(struct id_range *range, size_t id)
{
    irq_lock_acquire(&range->lock);
    if(range->next_avail == id + 1)
    {
        range->next_avail = id;
    }
    irq_lock_release(&range->lock);
    return 0;
}

#endif
