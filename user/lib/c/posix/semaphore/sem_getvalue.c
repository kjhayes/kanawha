
#include <semaphore.h>

int
sem_getvalue(sem_t *sem, int *out)
{
    // TODO: This should probably be an atomic load of some sort
    *out = sem->value;
    return 0;
}
