#ifndef __KANAWHA__LOCK_H__
#define __KANAWHA__LOCK_H__

#include <kanawha/atomic.h>
#include <kanawha/attribute.h>
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

typedef struct thread_lock
{
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
    int prev = atomic_bool_test_and_set(&lock->locked);
    DEBUG_ASSERT_MSG(prev == 0 || prev == 1,
                     "Corrupted thread_lock! (value other than 0 or 1)");
    return prev;
}

// Blocks until the lock can be acquired
static inline void
thread_lock_acquire(thread_lock_t *lock)
{
    while(atomic_bool_test_and_set(&lock->locked))
    {
        pause();
    }
}

static inline void
thread_lock_release(thread_lock_t *lock)
{
    atomic_bool_clear(&lock->locked);
}

static inline void
thread_lock_acquire_pair(thread_lock_t *a, thread_lock_t *b)
{
    if(a == b)
    {
        thread_lock_acquire(a);
        return;
    }

    thread_lock_t *lesser = (uintptr_t)a < (uintptr_t)b ? a : b;
    thread_lock_t *greater = lesser == a ? b : a;

    thread_lock_acquire(lesser);
    thread_lock_acquire(greater);

    return;
}

#define DECLARE_QUALIFIED_THREAD_LOCK(__name, __qual)                          \
    __qual thread_lock_t __lock_##__name;                                      \
    __qual void __name##_acquire(void);                                        \
    __qual void __name##_release(void);

#define DEFINE_QUALIFIED_THREAD_LOCK(__name, __qual)                           \
    __qual thread_lock_t __lock_##__name = {                                   \
        .locked = 0,                                                           \
    };                                                                         \
    __maybe_unused __qual void __name##_try_acquire(void)                      \
    {                                                                          \
        thread_lock_try_acquire(&__lock_##__name);                             \
    }                                                                          \
    __qual void __name##_acquire(void)                                         \
    {                                                                          \
        thread_lock_acquire(&__lock_##__name);                                 \
    }                                                                          \
    __qual void __name##_release(void)                                         \
    {                                                                          \
        thread_lock_release(&__lock_##__name);                                 \
    }

#define DECLARE_GLOBAL_THREAD_LOCK(__name)                                     \
    DECLARE_QUALIFIED_THREAD_LOCK(__name, extern)
#define DEFINE_GLOBAL_THREAD_LOCK(__name) DEFINE_QUALIFIED_THREAD_LOCK(__name, )

#define DECLARE_LOCAL_THREAD_LOCK(__name)                                      \
    DECLARE_QUALIFIED_THREAD_LOCK(__name, static)
#define DEFINE_LOCAL_THREAD_LOCK(__name)                                       \
    DEFINE_QUALIFIED_THREAD_LOCK(__name, static)

#define THREAD_LOCK_INITIALIZER                                                \
    {                                                                          \
        .locked = 0,                                                           \
        .irq_flags = 0,                                                        \
    }

// "irq" lock
//
// This lock should be safe from interrupt contextes,
// and for gaurding between interrupt contextes,
// however, it does not make any promises about preemption,
// (a thread could still yield the CPU without error while the lock is held)

typedef struct irq_lock irq_lock_t;

typedef struct irq_lock
{
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
    DEBUG_ASSERT_MSG(prev == 0 || prev == 1,
                     "Corrupted irq_lock! (value other than 0 or 1)");
    if(prev == 0)
    {
        // We got the lock
        lock->irq_flags = irq_flags;
        return 0;
    }
    else
    {
        // We failed to get the lock
        enable_restore_irqs(irq_flags);
        return 1;
    }
}

static inline void
irq_lock_acquire(irq_lock_t *lock)
{
    while(irq_lock_try_acquire(lock))
    {
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

static inline int
irq_lock_release_no_enable_irqs(irq_lock_t *lock)
{
    int irq_flags = lock->irq_flags;
    mbarrier();
    atomic_bool_clear(&lock->locked);
    return irq_flags;
}

static inline void
irq_lock_acquire_pair(irq_lock_t *a, irq_lock_t *b)
{
    int res;

    if(a == b)
    {
        irq_lock_acquire(a);
        return;
    }

    irq_lock_t *lesser = (uintptr_t)a < (uintptr_t)b ? a : b;
    irq_lock_t *greater = lesser == a ? b : a;

    do
    {

        res = irq_lock_try_acquire(lesser);
        if(res)
        {
            pause();
            continue;
        }
        res = irq_lock_try_acquire(greater);
        if(res)
        {
            irq_lock_release(lesser);
            pause();
            continue;
        }
        break;
    } while(1);
}

#define DECLARE_QUALIFIED_IRQ_LOCK(__name, __qual)                             \
    __qual irq_lock_t __irq_lock_##__name;                                     \
    __qual void __name##_try_acquire(void);                                    \
    __qual void __name##_acquire(void);                                        \
    __qual void __name##_release(void);

#define DEFINE_QUALIFIED_IRQ_LOCK(__name, __qual)                              \
    __qual irq_lock_t __lock_##__name = {                                      \
        .locked = 0,                                                           \
        .irq_flags = 0,                                                        \
    };                                                                         \
    __maybe_unused __qual void __name##_try_acquire(void)                      \
    {                                                                          \
        irq_lock_try_acquire(&__lock_##__name);                                \
    }                                                                          \
    __qual void __name##_acquire(void) { irq_lock_acquire(&__lock_##__name); } \
    __qual void __name##_release(void) { irq_lock_release(&__lock_##__name); }

#define DECLARE_GLOBAL_IRQ_LOCK(__name)                                        \
    DECLARE_QUALIFIED_IRQ_LOCK(__name, extern)
#define DEFINE_GLOBAL_IRQ_LOCK(__name) DEFINE_QUALIFIED_IRQ_LOCK(__name, )

#define DECLARE_LOCAL_IRQ_LOCK(__name)                                         \
    DECLARE_QUALIFIED_IRQ_LOCK(__name, static)
#define DEFINE_LOCAL_IRQ_LOCK(__name) DEFINE_QUALIFIED_IRQ_LOCK(__name, static)

#define IRQ_LOCK_INITIALIZER                                                   \
    {                                                                          \
        .locked = 0,                                                           \
        .irq_flags = 0,                                                        \
    }

#endif
