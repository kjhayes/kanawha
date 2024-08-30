#ifndef __KANAWHA__SPINLOCK_H__
#define __KANAWHA__SPINLOCK_H__

#include <kanawha/atomic.h>
#include <kanawha/stdint.h>
#include <kanawha/errno.h>

typedef atomic_bool_t spinlock_t;

static inline void spinlock_init(spinlock_t *lock);
static inline void spin_lock(spinlock_t *lock);
static inline void spin_unlock(spinlock_t *lock);

static inline void
spinlock_init(spinlock_t *lock) {
    atomic_bool_set_relaxed(lock, 0);
}

// Returns 0 on success
static inline int
spin_try_lock(spinlock_t *lock) {
    int val = atomic_bool_test_and_set(lock);
    return val;
}

static inline void
spin_lock(spinlock_t *lock) {
    while(spin_try_lock(lock)) {}
}

static inline void
spin_unlock(spinlock_t *lock) {
    atomic_bool_clear(lock);
}

#define DECLARE_SPINLOCK(__lock)\
    spinlock_t __lock = (atomic_bool_t)0;
#define INIT_SPINLOCK_FIELD(__field)\
    .__field = (atomic_bool_t)0

#endif
