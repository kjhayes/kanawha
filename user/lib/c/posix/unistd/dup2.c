
#include <unistd.h>
#include <fcntl.h>

int
dup2(int filedes1, int filedes2)
{
    close(filedes2);
    return fcntl(filedes1, F_DUPFD, filedes2);
}
