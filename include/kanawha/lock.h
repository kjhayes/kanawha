#ifndef __KANAWHA__LOCK_H__
#define __KANAWHA__LOCK_H__

#include <kanawha/atomic.h>
#include <kanawha/common.h>
#include <kanawha/irq.h>
#include <kanawha/mbarrier.h>

// "thread" lock
//
// Users should not assume that this is a spinlock,
// This lock is only meant to be safe for locking
// between two different kernel threads, it is NOT
// safe between threads and interrupt contextes or,
// between two different interrupt contextes,
// and makes no promises about preemption

typedef struct thread_lock thread_lock_t;

typedef struct thread_lock {
    atomic_bool_t locked;
} thread_lock_t;

static inline int
thread_lock_init(thread_lock_t *lock)
{
    atomic_bool_set_relaxed(&lock->locked, 0);
    return 0;
}

// Returns 0 if the lock is acquired, non-zero otherwise
static inline int
thread_lock_try_acquire(thread_lock_t *lock)
{
    return atomic_bool_test_and_set(&lock->locked);
}

// Blocks until the lock can be acquired
static inline void
thread_lock_acquire(thread_lock_t *lock)
{
    while(atomic_bool_test_and_set(&lock->locked)) {
        pause();
    }
}

static inline void
thread_lock_release(thread_lock_t *lock)
{
    atomic_bool_clear(&lock->locked);
}

// "irq" lock
//
// This lock should be safe from interrupt contextes,
// and for gaurding between interrupt contextes,
// however, it does not make any promises about preemption,
// (a thread could still yield the CPU without error while the lock is held)

typedef struct irq_lock irq_lock_t;

typedef struct irq_lock {
    atomic_bool_t locked;
    int irq_flags;
} irq_lock_t;

static inline int
irq_lock_init(irq_lock_t *lock)
{
    atomic_bool_set_relaxed(&lock->locked, 0);
    lock->irq_flags = 0;
    return 0;
}

static inline int
irq_lock_try_acquire(irq_lock_t *lock)
{
    int irq_flags = disable_save_irqs();
    int prev = atomic_bool_test_and_set(&lock->locked);
    if(prev == 0) {
        // We got the lock
        lock->irq_flags = irq_flags;
        return 0;
    } else {
        // We failed to get the lock
        enable_restore_irqs(irq_flags);
        return 1;
    }
}

static inline void
irq_lock_acquire(irq_lock_t *lock)
{
    while(irq_lock_try_acquire(lock)) {
        pause();
    }
}

static inline void
irq_lock_release(irq_lock_t *lock)
{
    int irq_flags = lock->irq_flags;
    mbarrier();
    atomic_bool_clear(&lock->locked);
    enable_restore_irqs(irq_flags);
}

#endif
