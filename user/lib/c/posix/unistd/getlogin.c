
#include <unistd.h>
#include <string.h>
#include <errno.h>

char *
getlogin(void)
{
#define GETLOGIN_BUFLEN 32

    int res;

    static char buffer[GETLOGIN_BUFLEN];
   
    res = getlogin_r(buffer, (size_t)GETLOGIN_BUFLEN);
    if(res) {
	errno = res;
	return NULL;
    }

    buffer[GETLOGIN_BUFLEN-1] = '\0';

    return buffer;

#undef GETLOGIN_BUFLEN
}

int
getlogin_r(
	char *buf,
	size_t bufsize)
{
    return -EINVAL;
}

