#ifndef __KANAWHA__SPINLOCK_H__
#define __KANAWHA__SPINLOCK_H__

#include <kanawha/assert.h>
#include <kanawha/atomic.h>
#include <kanawha/errno.h>
#include <kanawha/printk.h>
#include <kanawha/types.h>

typedef struct
{
    atomic_bool_t held;
} spinlock_t;

static inline void
spinlock_init(spinlock_t *lock);
static inline void
spin_lock(spinlock_t *lock);
static inline void
spin_unlock(spinlock_t *lock);

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

void
spinlock_failed_loop(spinlock_t *lock);

static inline void
spin_lock(spinlock_t *lock)
{
    while(spin_try_lock(lock))
    {
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

static inline void
spin_lock_pair(spinlock_t *lock_0, spinlock_t *lock_1)
{
    DEBUG_ASSERT(lock_0 != lock_1);

    spinlock_t *lesser =
        (uintptr_t)lock_0 < (uintptr_t)lock_1 ? lock_0 : lock_1;
    spinlock_t *greater =
        (uintptr_t)lock_0 > (uintptr_t)lock_1 ? lock_0 : lock_1;

    spin_lock(lesser);
    spin_lock(greater);
}

#ifndef CONFIG_DEBUG_SPINLOCK_TRACK_THREADS
#define DECLARE_SPINLOCK(__lock)                                               \
    spinlock_t __lock = {                                                      \
        .held = (atomic_bool_t)0,                                              \
    }
#define INIT_SPINLOCK_FIELD(__field)                                           \
    .__field = {                                                               \
        .held = (atomic_bool_t)0,                                              \
    }
#endif

#endif
