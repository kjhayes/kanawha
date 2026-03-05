
#include <fcntl.h>
#include <unistd.h>

int
dup(int filedes)
{
    return fcntl(filedes, F_DUPFD, 0);
}
