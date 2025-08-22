
#include <termios.h>

int
cfsetspeed(
	struct termios *termios_p,
	speed_t speed)
{
    // Input/Output speeds are the same
    return cfsetospeed(termios_p, speed);
}

