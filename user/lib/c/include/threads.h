#ifndef __ELK_LIBC__THREADS_H__
#define __ELK_LIBC__THREADS_H__

#include <time.h>

#define thread_local _Thread_local
#define ONCE_FLAG_INIT (0)
#define TSS_DTOR_ITERATIONS (0)

enum
{
    thrd_busy,
    thrd_error,
    thrd_nomem,
    thrd_success,
    thrd_timedout,
};

typedef struct
{
    pid_t pid;
} thrd_t;

typedef int (*thrd_start_t)(void *);

int
thrd_create(thrd_t *, thrd_start_t, void *);
thrd_t
thrd_current(void);
int thrd_detach(thrd_t);
int thrd_equal(thrd_t, thrd_t);
_Noreturn void
thrd_exit(int);
int
thrd_join(thrd_t, int *);
int
thrd_sleep(const struct timespec *, struct timespec *);
void
thrd_yield(void);

/*
 * We don't implement call_once yet
 */

// typedef struct {} once_flag;

// void            call_once(once_flag *, void (*)(void));

/*
 * We don't implement mutexes yet...
 */

// enum {
//     mtx_plain,
//     mtx_recursive,
//     mtx_timed,
// };

// typedef struct {} mtx_t;

// void            mtx_destroy(mtx_t *);
// int             mtx_init(mtx_t *, int);
// int             mtx_lock(mtx_t *);
// int             mtx_timedlock(mtx_t * restrict,
//                     const struct timespec * restrict);
// int             mtx_trylock(mtx_t *);
// int             mtx_unlock(mtx_t *);

/*
 * We don't implement cnd vars yet...
 */

// typedef struct {} cnd_t;

// int             cnd_broadcast(cnd_t *);
// void            cnd_destroy(cnd_t *);
// int             cnd_init(cnd_t *);
// int             cnd_signal(cnd_t *);
// int             cnd_timedwait(cnd_t * restrict, mtx_t * restrict,
//                     const struct timespec * restrict);
// int             cnd_wait(cnd_t *, mtx_t *);

/*
 * We don't implement TSS yet...
 */

// typedef struct {} tss_t;
// typedef void(*tss_dtor_t)(void*);

// int             tss_create(tss_t *, tss_dtor_t);
// void            tss_delete(tss_t);
// void           *tss_get(tss_t);
// int             tss_set(tss_t, void *);

#endif
