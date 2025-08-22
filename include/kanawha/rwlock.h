#ifndef __KANAWHA__RWLOCK_H__
#define __KANAWHA__RWLOCK_H__

#include <kanawha/atomic.h>
#include <kanawha/lock.h>

// Reader Preferred Lock
// (Readers are able to starve writers)
typedef struct rlock {
    size_t readers;
    irq_lock_t read_lock;
    irq_lock_t full_lock;
} rlock_t;

static inline void
rlock_read_lock(rlock_t *lock) {
    irq_lock_acquire(&lock->read_lock);
    if(lock->readers == 0) {
        irq_lock_acquire(&lock->full_lock);
    }
    lock->readers++;
    irq_lock_release(&lock->read_lock);
}

static inline void
rlock_read_unlock(rlock_t *lock) {
    irq_lock_acquire(&lock->read_lock);
    lock->readers--;
    if(lock->readers == 0) {
        irq_lock_release(&lock->full_lock);
    }
    irq_lock_release(&lock->read_lock);
}

static inline void
rlock_write_lock(rlock_t *lock) {
    irq_lock_acquire(&lock->full_lock);
}

static inline void
rlock_write_unlock(rlock_t *lock) {
    irq_lock_release(&lock->full_lock);
}

static inline void
rlock_init(rlock_t *lock) {
    lock->readers = 0;
    irq_lock_init(&lock->read_lock);
    irq_lock_init(&lock->full_lock);
}

#define DECLARE_RLOCK(__var)\
    rlock_t __var = {\
        .readers = 0,\
        .read_lock = IRQ_LOCK_INITIALIZER,\
        .full_lock = IRQ_LOCK_INITIALIZER,\
    };

#endif
