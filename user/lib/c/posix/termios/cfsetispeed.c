
#include <termios.h>

int
cfsetispeed(struct termios *termios_p, speed_t speed)
{
    if(speed == 0)
    {
        // Same as output speed
        return 0;
    }
    // Do not support setting different
    // Input/Output speeds
    return -1;
}
