
#include <elk-libc-internal/__sFILE.h>
#include <stdio.h>
#include <unistd.h>

int
ftrylockfile(FILE *filehandle)
{
    int res;
    res = sem_trywait(&filehandle->owner_sem);
    if(res)
    {
        return res;
    }
    filehandle->owner_pid = getpid();
}
