#ifndef __KANAWHA__SPINLOCK_H__
#define __KANAWHA__SPINLOCK_H__

#include <kanawha/atomic.h>
#include <kanawha/stdint.h>
#include <kanawha/errno.h>
#include <kanawha/printk.h>

#ifdef CONFIG_DEBUG_SPINLOCK_TRACK_THREADS

extern struct thread_state *
current_thread(void);

static int
__debug_spinlock_tracking_enabled = 0;

static inline int
debug_spinlock_tracking(void)
{
    return __debug_spinlock_tracking_enabled;
}

#endif


typedef struct {
    atomic_bool_t held;
#ifdef CONFIG_DEBUG_SPINLOCK_TRACK_THREADS
    struct thread_state *held_by;
#endif
} spinlock_t;

static inline void spinlock_init(spinlock_t *lock);
static inline void spin_lock(spinlock_t *lock);
static inline void spin_unlock(spinlock_t *lock);

static inline void
spinlock_init(spinlock_t *lock) {
    atomic_bool_set_relaxed(&lock->held, 0);
#ifdef CONFIG_DEBUG_SPINLOCK_TRACK_THREADS
    lock->held_by = NULL;
#endif
}

// Returns 0 on success
static inline int
spin_try_lock(spinlock_t *lock) {
    int val = atomic_bool_test_and_set(&lock->held);
#ifdef CONFIG_DEBUG_SPINLOCK_TRACK_THREADS
    if(debug_spinlock_tracking() && val) {
        lock->held_by = current_thread();
    }
#endif
    return val;
}

static inline void
spin_lock(spinlock_t *lock) {
    while(spin_try_lock(lock)) {
#ifdef CONFIG_DEBUG_SPINLOCK_TRACK_THREADS
        if(debug_spinlock_tracking() &&
           (lock->held_by != NULL) &&
           (lock->held_by == current_thread())) {
            panic("DEADLOCK Detected! lock->held_by == current_thread() == %p\n",
                    lock->held_by);
        }
#endif
    }
}

static inline void
spin_unlock(spinlock_t *lock) {
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
#else
#define DECLARE_SPINLOCK(__lock)\
    spinlock_t __lock = {\
        .held = (atomic_bool_t)0, \
        .held_by = NULL, \
    }
#define INIT_SPINLOCK_FIELD(__field)\
    .__field = { \
        .held = (atomic_bool_t)0, \
        .held_by = NULL, \
    }
#endif

#endif
