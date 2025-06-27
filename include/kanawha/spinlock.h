#ifndef __KANAWHA__SPINLOCK_H__
#define __KANAWHA__SPINLOCK_H__

#include <kanawha/atomic.h>
#include <kanawha/types.h>
#include <kanawha/errno.h>
#include <kanawha/printk.h>
#include <kanawha/assert.h>

typedef struct {
    atomic_bool_t held;
} spinlock_t;

static inline void spinlock_init(spinlock_t *lock);
static inline void spin_lock(spinlock_t *lock);
static inline void spin_unlock(spinlock_t *lock);

static inline void
spinlock_init(spinlock_t *lock)
{
    DEBUG_ASSERT(KERNEL_ADDR(lock));
    atomic_bool_set_relaxed(&lock->held, 0);
}

// Returns 0 on success
static inline int
spin_try_lock(spinlock_t *lock)
{
    DEBUG_ASSERT(KERNEL_ADDR(lock));
    int val = atomic_bool_test_and_set(&lock->held);
    return val;
}

void spinlock_failed_loop(spinlock_t *lock);

static inline void
spin_lock(spinlock_t *lock)
{
    while(spin_try_lock(lock)) {
        // "pause" and check for deadlock
        spinlock_failed_loop(lock);
    }
}

static inline void
spin_unlock(spinlock_t *lock)
{
    DEBUG_ASSERT(KERNEL_ADDR(lock));
    atomic_bool_clear(&lock->held);
}

#ifndef CONFIG_DEBUG_SPINLOCK_TRACK_THREADS
#define DECLARE_SPINLOCK(__lock)\
    spinlock_t __lock = {\
        .held = (atomic_bool_t)0, \
    }
#define INIT_SPINLOCK_FIELD(__field)\
    .__field = { \
        .held = (atomic_bool_t)0, \
    }
#endif

#endif
