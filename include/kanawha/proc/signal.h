#ifndef __KANAWHA__PROC_SIGNAL_H__
#define __KANAWHA__PROC_SIGNAL_H__

#include <kanawha/uapi/signal.h>
#include <kanawha/uapi/process.h>
#include <kanawha/usermode.h>
#include <kanawha/bitmap.h>
#include <kanawha/lock.h>

#define NUM_SIGNALS (256)

struct process;

struct signal_state
{
    irq_lock_t lock;

    // Where user-space has asked us to set IP
    // on signal delivery
    void __user *signal_entry;
    int signal_entry_set;

    // Pending Information
    unsigned long num_pending; // Number of bits set in the pending bitmap
    DECLARE_BITMAP(pending_bitmap, NUM_SIGNALS);

    unsigned int fatal;

    // Are we currently running a signal handler?
    unsigned int interrupted;
    void __user *interrupted_user_ip;
};

int
signal_state_init(struct signal_state *state);
int
signal_state_init_on_spawn(
	struct signal_state *parent,
	struct signal_state *child);

#define SIGNAL_FLAG_COALESCE (1ULL<<0) // Make assertion of this signal idempotent
#define SIGNAL_FLAG_IGNORABLE (1ULL<<1) // Don't wake the thread if it is asleep.
#define SIGNAL_FLAG_FATAL (1ULL<<2) // Terminate the process on signal delivery.
int
signal_deliver(
        struct process *process,
        signal_id_t id,
        unsigned long flags);

int
signal_ack(
	struct process *process,
	signal_id_t id);

int
signal_set_entry(
        struct process *process,
        void __user *entry);

int
signal_on_return_to_userspace(
	struct process *process);

signal_id_t
process_current_signal(
	struct process *process);

void __user *
process_signal_return_addr(
	struct process *process);

const char *
signal_id_string(signal_id_t id);

#endif
