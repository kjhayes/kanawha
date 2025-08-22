
#include <kanawha/proc/signal.h>
#include <kanawha/proc/process.h>
#include <kanawha/uapi/signal.h>
#include <kanawha/strace.h>
#include <kanawha/spinlock.h>
#include <kanawha/irq.h>
#include <kanawha/string.h>

int
signal_state_init(
        struct signal_state *state)
{
    irq_lock_init(&state->lock);

    state->signal_entry = NULL;
    state->signal_entry_set = 0;

    state->interrupted_user_ip  = 0;
    state->interrupted = 0;

    state->num_pending = 0;
    memset(state->pending_bitmap, 0, sizeof(state->pending_bitmap));

    return 0;
}

int
signal_state_init_on_spawn(
	struct signal_state *parent,
	struct signal_state *child)
{
    int res;

    irq_lock_acquire(&parent->lock);

    child->signal_entry = parent->signal_entry;
    child->signal_entry_set = parent->signal_entry_set;

    irq_lock_release(&parent->lock);

    return 0;
}

int
signal_deliver(
        struct process *process,
        signal_id_t id,
        unsigned long flags)
{
    int res;
    irq_lock_acquire(&process->signal_state.lock);

    strace_deliver_signal(process, id);

    if(bitmap_check(process->signal_state.pending_bitmap, id)) {
	// The signal is already pending
        irq_lock_release(&process->signal_state.lock);

	if((flags & SIGNAL_FLAG_COALESCE) == 0) {
	    return -EALREADY;
	}

	return 0;
    }

    bitmap_set(process->signal_state.pending_bitmap, id);
    process->signal_state.num_pending++;

    irq_lock_release(&process->signal_state.lock);

    return 0;
}

int
signal_ack(
	struct process *process,
	signal_id_t id)
{
    int res;

    irq_lock_acquire(&process->signal_state.lock);

    process->signal_state.interrupted = 0;

    if(bitmap_check(process->signal_state.pending_bitmap, id)) {
	process->signal_state.num_pending--;
	bitmap_clear(process->signal_state.pending_bitmap, id);
    }

    irq_lock_release(&process->signal_state.lock);

    return 0;
}

int
signal_on_return_to_userspace(
	struct process *process)
{
    int res;

    irq_lock_acquire(&process->signal_state.lock);

    if(process->signal_state.num_pending == 0) {
        irq_lock_release(&process->signal_state.lock);
	return 0; // Nothing to do
    }

    if(process->signal_state.interrupted) {
        irq_lock_release(&process->signal_state.lock);
	return 0; // Can't deliver another signal
    }

    if(process->signal_state.signal_entry_set == 0) {
        irq_lock_release(&process->signal_state.lock);
	return -EINVAL; // No entry point set
    }

    signal_id_t id = bitmap_find_first_set(process->signal_state.pending_bitmap, NUM_SIGNALS);
    DEBUG_ASSERT(id < NUM_SIGNALS);

    process->signal_state.interrupted_user_ip = process->user_ip;
    process->user_ip = process->signal_state.signal_entry;
    process->signal_state.interrupted = 1;

    printk("Delivering Signal to Userspace: interrupted=%p, entry=%p\n",
	    process->signal_state.interrupted_user_ip,
	    process->user_ip);

    irq_lock_release(&process->signal_state.lock);

    return 0;
}

int
signal_set_entry(
        struct process *process,
        void __user *entry)
{
    irq_lock_acquire(&process->signal_state.lock);

    process->signal_state.signal_entry_set = 1;
    process->signal_state.signal_entry = entry;

    irq_lock_release(&process->signal_state.lock);
    return 0;
}

signal_id_t
process_current_signal(
	struct process *process)
{
    signal_id_t sig;

    irq_lock_acquire(&process->signal_state.lock);

    sig = bitmap_find_first_set(process->signal_state.pending_bitmap, NUM_SIGNALS);
    if(sig == NUM_SIGNALS) {
	sig = SIGNAL_ID_NONE;
    }

    irq_lock_release(&process->signal_state.lock);

    return sig;
}

void __user *
process_signal_return_addr(
	struct process *process)
{
    void __user *addr;

    irq_lock_acquire(&process->signal_state.lock);

    addr = process->signal_state.interrupted_user_ip;

    irq_lock_release(&process->signal_state.lock);

    return addr;
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

