
#include <elk-libc-internal/__sFILE.h>
#include <semaphore.h>
#include <stdio.h>
#include <unistd.h>

void
funlockfile(FILE *filehandle)
{
    int res;
    do {
        res = sem_wait(&filehandle->owner_sem);
    } while(res != 0);

    filehandle->owner_pid = -1;

    sem_post(&filehandle->owner_sem);
}
