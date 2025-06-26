
#include <kanawha/proc/signal.h>
#include <kanawha/proc/process.h>
#include <kanawha/uapi/signal.h>
#include <kanawha/strace.h>
#include <kanawha/spinlock.h>
#include <kanawha/irq.h>

int
signal_state_init(
        struct signal_state *state)
{
    spinlock_init(&state->lock);

    state->in_signal = 0;
    state->current_signal = 0;

    state->signal_entry = NULL;
    state->signal_entry_set = 0;

    state->signal_return_ip = NULL;

    return 0;
}

int
signal_deliver(
        struct process *process,
        signal_id_t id,
        unsigned long flags)
{
    int res;
    int irq_flags = spin_lock_irq_save(&process->signal_state.lock);

    strace_deliver_signal(process, id);

    if(process->signal_state.in_signal) {
        // Cannot send another signal while within a signal
        spin_unlock_irq_restore(&process->signal_state.lock, irq_flags);
        return -EALREADY;
    }

    // The process didn't set a signal handler
    if(!process->signal_state.signal_entry_set) {
        spin_unlock_irq_restore(&process->signal_state.lock, irq_flags);
        return -EINVAL;
    }

    process->signal_state.in_signal = 1;
    process->signal_state.signal_delivered = 0;
    process->signal_state.current_signal = id;

    // Set the new return address
    process->signal_state.signal_return_ip = process->user_ip;
    process->user_ip = process->signal_state.signal_entry;

    spin_unlock_irq_restore(&process->signal_state.lock, irq_flags);
    return 0;
}

int
signal_complete(
        struct process *process
        )
{
    int irq_flags = spin_lock_irq_save(&process->signal_state.lock);

    if(!process->signal_state.in_signal) {
        spin_unlock_irq_restore(&process->signal_state.lock, irq_flags);
        return -EINVAL;
    }

    process->signal_state.in_signal = 0;
    process->signal_state.signal_delivered = 0;
    process->user_ip = process->signal_state.signal_return_ip;

    spin_unlock_irq_restore(&process->signal_state.lock, irq_flags);
    return 0;
}

int
signal_set_entry(
        struct process *process,
        void __user *entry)
{
    int irq_flags = spin_lock_irq_save(&process->signal_state.lock);

    process->signal_state.signal_entry_set = 1;
    process->signal_state.signal_entry = entry;

    spin_unlock_irq_restore(&process->signal_state.lock, irq_flags);
    return 0;
}

const char *
signal_id_string(signal_id_t id)
{
    switch(id) {
#define SIGNAL_ID_STRING_CASE(__ID, __NAME, ...)\
        case SIGNAL_ID_ ## __NAME:\
            return #__NAME;

        SIGNAL_XLIST(SIGNAL_ID_STRING_CASE)
#undef SIGNAL_ID_STRING_CASE

        default:
            return "UNKNOWN";
    }
}

