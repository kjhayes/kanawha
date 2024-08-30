#ifndef __KANAWHA__IRQ_H__
#define __KANAWHA__IRQ_H__

#include <kanawha/common.h>
#include <kanawha/stdint.h>
#include <kanawha/spinlock.h>

#define NULL_IRQ ((irq_t)(-1))
typedef uint32_t irq_t;
typedef uint32_t hwirq_t;

#define IRQ_MAX (~(uint32_t)0)

int arch_irq_disable(void);
int arch_irq_enable(void);
int arch_irqs_enabled(void);

static inline int 
disable_irqs(void) {
    return arch_irq_disable();
}

static inline int
enable_irqs(void) {
    return arch_irq_enable();
}

static inline int
irqs_enabled(void) {
    return arch_irqs_enabled();
}

static DECLARE_SPINLOCK(disable_irqs_lock);

static inline int
disable_save_irqs(void) {
    spin_lock(&disable_irqs_lock);
    int state = irqs_enabled();
    if(state) {
        disable_irqs();
    }
    spin_unlock(&disable_irqs_lock);
    return state;
}

static inline void
enable_restore_irqs(int state)
{
    if(state) {
        spin_lock(&disable_irqs_lock);
        enable_irqs();
        spin_unlock(&disable_irqs_lock);
    }
}

static inline int
spin_lock_irq_save(spinlock_t *lock) {
    do {
    int state = disable_save_irqs();
    if(!spin_try_lock(lock)) {
        return state;
    }
    enable_restore_irqs(state);
    } while(1);
}


static inline void
spin_unlock_irq_restore(spinlock_t *lock, int irq_state)
{
    spin_unlock(lock);
    enable_restore_irqs(irq_state);
}

static inline int
spin_lock_pair_irq_save(spinlock_t *lock_0, spinlock_t *lock_1)
{
    if(lock_0 == lock_1) {
        return spin_lock_irq_save(lock_0);
    }

    spinlock_t *lesser = (uintptr_t)lock_0 < (uintptr_t)lock_1 ? lock_0 : lock_1;
    spinlock_t *greater = (uintptr_t)lock_0 > (uintptr_t)lock_1 ? lock_0 : lock_1;
    do {
    int state = disable_save_irqs();
    if(!spin_try_lock(lesser)) {
        if(!spin_try_lock(greater)) {
            return state;
        }
        spin_unlock(lesser);
    }
    enable_restore_irqs(state);
    pause();
    } while(1);
}

static inline void
spin_unlock_pair_irq_restore(spinlock_t *lock_0, spinlock_t *lock_1, int flags) {
    if(lock_0 == lock_1) {
        spin_unlock_irq_restore(lock_0, flags);
        return;
    }

    spinlock_t *lesser = (uintptr_t)lock_0 < (uintptr_t)lock_1 ? lock_0 : lock_1;
    spinlock_t *greater = (uintptr_t)lock_0 > (uintptr_t)lock_1 ? lock_0 : lock_1;
    spin_unlock(greater);
    spin_unlock(lesser);
    enable_restore_irqs(flags);
}

#endif
