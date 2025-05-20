
#include <signal.h>
#include <stdint.h>

void(*signal(int sig, void(*func)(int)))(int)
{
    if(func == SIG_DFL) {
        // TODO set errno
        return SIG_ERR;
    } else if(func == SIG_ERR) {
        // TODO set errno
        return SIG_ERR;
    } else if(func == SIG_HOLD) {
        // TODO set errno
        return SIG_ERR;
    } else if(func == SIG_IGN) {
        // TODO set errno
        return SIG_ERR;
    } else {
        // TODO set errno
        return SIG_ERR;       
    }
}

