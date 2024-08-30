#ifndef __KANAWHA__REFCOUNT_H__
#define __KANAWHA__REFCOUNT_H__

#include <kanawha/spinlock.h>
#include <kanawha/errno.h>

typedef struct {
    unsigned long refs;
    int alive;
    spinlock_t lock;
} refcount_t;

static inline void refcount_init(refcount_t *count);

// Returns zero on sucess (errno on error)
static inline int refcount_kill(refcount_t *count);
// Returns non-zero if this refcount is alive (regardless of the number of refs)
static inline int refcount_alive(refcount_t *count);
// Returns non-zero if this refcount is dead (regardless of the number of refs)
static inline int refcount_dead(refcount_t *count);
// Returns non-zero if this refcount is dead, and has zero refs
static inline int refcount_reapable(refcount_t *count);

// Returns positive or zero number of references after operation
// Returns negative errno on failure
static inline int refcount_inc(refcount_t *count);
static inline int refcount_dec(refcount_t *count);

/*
 * Implementation
 */
static inline void
refcount_init(refcount_t *count) {
    count->refs = 0;
    count->alive = 1;
    spinlock_init(&count->lock);
}

static inline int
refcount_kill(refcount_t *count) {
    int ret = 0;
    spin_lock(&count->lock);
    if(count->alive) {
        count->alive = 0;
    } else {
        ret = -EALREADY;
    }
    spin_unlock(&count->lock);
    return ret;
}

static inline int
refcount_alive(refcount_t *count) 
{
    int ret;
    spin_lock(&count->lock);
    ret = count->alive;
    spin_unlock(&count->lock);
    return ret;
}

static inline int
refcount_dead(refcount_t *count)
{
    return !refcount_dead(count);
}

// Only kills the refcount if it would immediately be reapable
// Returns 1 if the refcount is reapable after, else 0
static inline int
refcount_euthanize(refcount_t *count) {
    int ret;
    spin_lock(&count->lock);
    if(count->refs == 0) {
        count->alive = 0;
        ret = 1;
    } else {
        ret = 0;
    }
    spin_unlock(&count->lock);
    return ret;
}

static inline int
refcount_reapable(refcount_t *count) 
{
    int ret;
    spin_lock(&count->lock);
    ret = (!count->alive) && (count->refs == 0);
    spin_unlock(&count->lock);
    return ret;
}

static inline int
refcount_inc(refcount_t *count) 
{
    int ret;
    spin_lock(&count->lock);
    if(count->alive) {
        count->refs++;
        ret = count->refs;
    } else {
        ret = -EINVAL;
    }
    spin_unlock(&count->lock);
    return ret;
}

static inline int
refcount_dec(refcount_t *count) 
{
    int ret;
    spin_lock(&count->lock);
    if(count->alive) {
        if(count->refs > 0) {
            count->refs--;
            ret = count->refs;
        } else {
            ret = -EINVAL;
        }
    } else {
        ret = -EINVAL;
    }
    spin_unlock(&count->lock);
    return ret;
}

#endif
