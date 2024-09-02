#ifndef __KANAWHA__ENV_H__
#define __KANAWHA__ENV_H__

#include <kanawha/stree.h>
#include <kanawha/stdint.h>
#include <kanawha/spinlock.h>

/*
 * For now, processes aren't going to be limited
 * to any length of environment variable (name or value)
 * or any maximum number of variables
 *
 * Because these variables are stored on the kernel heap currently,
 * in the future support will ideally need to be added for 1. limiting
 * the amount of memory/number of variables a process can take up and/or
 * 2. storing environment variables such that they can be swapped off to disk
 * and only cached in ram when they are needed.
 */

/*
 * As much as possible, Kanawha is trying not to make any assumptions about
 * the memory layout of a user process. Ideally, this means we don't even
 * assume that there is a stack present.
 *
 * This makes many things more difficult though, an example being
 * passing argc, argv, and envp through an "exec" memory layout
 * transition.
 *
 * To help with this, Kanawha explicitly stores environment variables for
 * processes, with a simple key-value store, which is inherited by child processes,
 * and survives the exec syscall.
 *
 * This allows user-level ABI's to pass envp more or less directly, and can
 * indirectly support argv by defining an environment variable "ARGV" which contains
 * the arguments to the process.
 */

struct process;

struct envvar {
    struct stree_node node;
    char *value;
};

struct environment {
    struct stree env_table;
};

int
environment_init_new(
        struct process *process);

int
environment_init_inherit(
        struct process *parent,
        struct process *child);

int
environment_deinit(
        struct process *process);


// Clears the environment variable "var_name"
// still returns 0 even if "var_name" didn't exist
int
environment_clear_var(
        struct process *process,
        const char *var_name);

int
environment_clear_all(
        struct process *process);

// Sets the environment variable "var_name" to "value"
// and creates the variable if it did not exist previously
int
environment_set(
        struct process *process,
        const char *var_name,
        const char *value);

// Returns NULL if "var_name" does not exist
//
// If "var_name" does exist, then it leaves
// the process' environment table locked, and
// returns a pointer to the value of key "var_name"
//
// The caller will then need to call environment_put_var
// to unlock the environment, (if NULL was returned, DO NOT CALL environment_put_var)
//
// Between the calls to environment_get_var and environment_put_var is 
// a critical section, and should not block under any circumstances.
const char *
environment_get_var(
        struct process *process,
        const char *var_name);

int
environment_put_var(
        struct process *process);

#endif
