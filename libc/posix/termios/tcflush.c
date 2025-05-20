
#include <termios.h>
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
                // TODO set errno
                return -1;
            }
            return 0;
        default:
            // TODO set errno
            return -1;
    }
}

