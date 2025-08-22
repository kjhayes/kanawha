#ifndef __ELK_POSIX__SEMAPHORE_H__
#define __ELK_POSIX__SEMAPHORE_H__

#include <fcntl.h>
#include <sys/types.h>

#define SEM_FAILED ((sem_t*)0)

typedef struct {
    long value;
} sem_t;

int    sem_close(sem_t *);
int    sem_destroy(sem_t *);
int    sem_getvalue(sem_t *, int *);
int    sem_init(sem_t *, int, unsigned int);
sem_t *sem_open(const char *, int, ...);
int    sem_post(sem_t *);
int    sem_trywait(sem_t *);
int    sem_unlink(const char *);
int    sem_wait(sem_t *);

#endif
