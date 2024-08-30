
#include <kanawha/usermode.h>
#include <kanawha/thread.h>

__attribute__((noreturn))
void enter_usermode(void __user *starting_address)
{
    struct thread_state *thread = current_thread();

    if(thread == NULL) {
        panic("CPU (%ld) called enter_usermode without a thread!\n",
                (sl_t)current_cpu_id());
    }

    int lock_irq_flags = spin_lock_irq_save(&thread->lock);

    thread->flags |= THREAD_FLAG_USER;

    spin_unlock_irq_restore(&thread->lock, lock_irq_flags);

    /*
     * This little "gap" here allows for an interrupt to occur while we are a "user"
     * thread, but we actually were still running in kernel mode,
     * so note, THREAD_FLAG_USER does not mean we must have been running user-mode
     * when an interrupt/exception occurs
     */

    arch_enter_usermode(starting_address);
}

