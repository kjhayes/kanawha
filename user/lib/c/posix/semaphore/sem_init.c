
#include <semaphore.h>

int
sem_init(sem_t *sem, int pshared, unsigned int value)
{
    sem->value = value;
    return 0;
}
