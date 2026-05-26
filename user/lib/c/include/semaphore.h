#ifndef __ELK_POSIX__SEMAPHORE_H__
#define __ELK_POSIX__SEMAPHORE_H__

#include <fcntl.h>
#include <sys/types.h>

#define SEM_FAILED ((sem_t *)0)

typedef struct
{
    int lock;
    long value;
    long waiting;
    long waiting_seq;
} sem_t;

int
sem_close(sem_t *);
int
sem_destroy(sem_t *);
int
sem_getvalue(sem_t *, int *);
int
sem_init(sem_t *, int, unsigned int);
sem_t *
sem_open(const char *, int, ...);
int
sem_post(sem_t *);
int
sem_trywait(sem_t *);
int
sem_unlink(const char *);
int
sem_wait(sem_t *);

static inline void
__elk_libc_sem_lock(sem_t *sem)
{
    while(__atomic_test_and_set(&sem->lock, __ATOMIC_ACQUIRE)) {}
}
static inline void
__elk_libc_sem_unlock(sem_t *sem)
{
    __atomic_clear(&sem->lock, __ATOMIC_RELEASE);
}

#endif
