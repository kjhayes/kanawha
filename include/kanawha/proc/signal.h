#ifndef __KANAWHA__PROC_SIGNAL_H__
#define __KANAWHA__PROC_SIGNAL_H__

#include <kanawha/uapi/signal.h>
#include <kanawha/uapi/process.h>
#include <kanawha/usermode.h>
#include <kanawha/spinlock.h>

struct process;

struct signal_state {
    spinlock_t lock;

    void __user *signal_return_ip;
    signal_id_t current_signal;
    unsigned int in_signal : 1;
    unsigned int signal_delivered : 1;

    void __user *signal_entry;
    unsigned int signal_entry_set : 1;
};

int
signal_state_init(struct signal_state *state);

int
signal_deliver(
        struct process *process,
        signal_id_t id,
        unsigned long flags);

int
signal_complete(
        struct process *process
        );

int
signal_set_entry(
        struct process *process,
        void __user *entry);

const char *
signal_id_string(signal_id_t id);

#endif
