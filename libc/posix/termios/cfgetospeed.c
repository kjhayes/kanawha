
#include <termios.h>

speed_t
cfgetospeed(const struct termios *termios_p)
{
    tcflag_t flag = termios_p->c_oflag;
    // TODO
    return B0;
}
