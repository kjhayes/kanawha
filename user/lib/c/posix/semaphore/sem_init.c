
#include <semaphore.h>

int
sem_init(sem_t *sem, int pshared, unsigned int value)
{
    sem->lock = 0;
    sem->value = value;
    sem->waiting = 0;
    sem->waiting_seq = 0;
    return 0;
}
