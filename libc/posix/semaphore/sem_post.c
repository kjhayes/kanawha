
#include <semaphore.h>

int sem_post(
	sem_t *sem)
{
    __atomic_fetch_add(&sem->value, 1, __ATOMIC_SEQ_CST);
    return 0;
}
