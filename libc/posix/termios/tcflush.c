
#include <termios.h>
#include <errno.h>
#include <kanawha/sys-wrappers.h>

int
tcflush(int filedes, int selector)
{
    int res;
    switch(selector) {
        case TCOFLUSH:
        case TCIFLUSH:
        case TCIOFLUSH:
            res = kanawha_sys_flush(filedes, 0);
            if(res) {
		errno = res;
                return -1;
            }
            return 0;
        default:
	    errno = -EINVAL;
            return -1;
    }
}

