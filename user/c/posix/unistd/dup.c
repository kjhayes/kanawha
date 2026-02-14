
#include <unistd.h>
#include <fcntl.h>

int
dup(int filedes)
{
    return fcntl(filedes, F_DUPFD, 0);
}

