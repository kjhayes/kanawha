#ifndef __KANAWHA__ATOMIC_H__
#define __KANAWHA__ATOMIC_H__

// Including architecture support
#ifdef CONFIG_X64
#include <arch/x64/atomic.h>
#endif

// Default type implementations
#ifndef ATOMIC_BOOL_TYPE
#define ATOMIC_BOOL_TYPE char
#endif
#ifndef ATOMIC_COUNTER_TYPE
#define ATOMIC_COUNTER_TYPE long
#endif
#ifndef ATOMIC_UCOUNTER_TYPE
#define ATOMIC_UCOUNTER_TYPE unsigned long
#endif

typedef ATOMIC_BOOL_TYPE atomic_bool_t;
typedef ATOMIC_COUNTER_TYPE atomic_t;
typedef ATOMIC_UCOUNTER_TYPE uatomic_t;

// External API Forward Declarations

/*
 * atomic_t
 */

static inline
atomic_t atomic_fetch_inc(atomic_t *);

static inline
atomic_t atomic_fetch_dec(atomic_t *);

#ifndef arch_atomic_fetch_inc
#define arch_atomic_fetch_inc(v) __atomic_fetch_add(v, 1, __ATOMIC_SEQ_CST)
#endif
#ifndef arch_atomic_fetch_dec
#define arch_atomic_fetch_dec(v) __atomic_fetch_sub(v, 1, __ATOMIC_SEQ_CST)
#endif

/*
 * atomic_bool_t
 */

// Sets the bool to non-zero and returns the previous value atomically
static inline
int atomic_bool_test_and_set(atomic_bool_t *);

// Sets the bool to zero atomically
static inline
void atomic_bool_clear(atomic_bool_t *);

// Reads the bool as zero or non-zero without modifying atomically
static inline
int atomic_bool_check(atomic_bool_t *);

// Sets the value of the bool to zero or non-zero without regard to atomicity
static inline
void atomic_bool_set_relaxed(atomic_bool_t *, int);

// Default function implementations
#ifndef arch_atomic_bool_test_and_set
#define arch_atomic_bool_test_and_set(b) __atomic_test_and_set(b, __ATOMIC_SEQ_CST)
#endif
#ifndef arch_atomic_bool_clear
#define arch_atomic_bool_clear(b) __atomic_clear(b, __ATOMIC_SEQ_CST)
#endif
#ifndef arch_atomic_bool_check
#define arch_atomic_bool_check(b) ({ atomic_bool_t ret; __atomic_load(b, &ret, __ATOMIC_SEQ_CST); ret; })
#endif
#ifndef arch_atomic_bool_set_relaxed
#define arch_atomic_bool_set_relaxed(b, val) do { *b = val; } while (0)
#endif

/*
 * Wrappers to enable type checking
 */
static inline atomic_t
atomic_fetch_inc(atomic_t *x)
{ return arch_atomic_fetch_inc(x); }

static inline atomic_t
atomic_fetch_dec(atomic_t *x)
{ return arch_atomic_fetch_dec(x); }


static inline int
atomic_bool_test_and_set(atomic_bool_t *x)
{ return arch_atomic_bool_test_and_set(x); }

static inline void
atomic_bool_clear(atomic_bool_t *x)
{ arch_atomic_bool_clear(x); }

static inline int
atomic_bool_check(atomic_bool_t *x) 
{ return arch_atomic_bool_check(x); }

static inline void
atomic_bool_set_relaxed(atomic_bool_t *x, int val)
{ arch_atomic_bool_set_relaxed(x, val); }

#endif
