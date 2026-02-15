
#include <termios.h>

int
cfsetospeed(
	struct termios *termios_p,
	speed_t speed)
{
    termios_p->baudrate = speed;
    return 0;
}
