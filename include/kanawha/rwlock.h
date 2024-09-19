#ifndef __KANAWHA__RWLOCK_H__
#define __KANAWHA__RWLOCK_H__

#include <kanawha/atomic.h>
#include <kanawha/spinlock.h>
#include <kanawha/irq.h>

// Reader Preferred Lock
// (Readers are able to starve writers)
typedef struct rlock {
    size_t readers;
    spinlock_t read_lock;
    spinlock_t full_lock;
    int full_lock_irq_flags;
} rlock_t;

static inline void
rlock_read_lock(rlock_t *lock) {
    int irq_state = spin_lock_irq_save(&lock->read_lock);
    if(lock->readers == 0) {
        spin_lock(&lock->full_lock);
    }
    lock->readers++;
    spin_unlock_irq_restore(&lock->read_lock, irq_state);
}

static inline void
rlock_read_unlock(rlock_t *lock) {
    int irq_flags = spin_lock_irq_save(&lock->read_lock);
    lock->readers--;
    if(lock->readers == 0) {
        spin_unlock(&lock->full_lock);
    }
    spin_unlock_irq_restore(&lock->read_lock, irq_flags);
}

static inline void
rlock_write_lock(rlock_t *lock) {
    lock->full_lock_irq_flags = spin_lock_irq_save(&lock->full_lock);
}

static inline void
rlock_write_unlock(rlock_t *lock) {
    spin_unlock_irq_restore(&lock->full_lock, lock->full_lock_irq_flags);
}

static inline void
rlock_init(rlock_t *lock) {
    lock->readers = 0;
    spinlock_init(&lock->read_lock);
    spinlock_init(&lock->full_lock);
}

#define DECLARE_RLOCK(__var)\
    rlock_t __var = {\
        .readers = 0,\
        INIT_SPINLOCK_FIELD(read_lock),\
        INIT_SPINLOCK_FIELD(full_lock),\
    };

#endif
