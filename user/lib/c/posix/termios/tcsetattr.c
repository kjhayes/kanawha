
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static int
__tcsetattr_set_baudrate(int filedes, const struct termios *termios_p)
{
    unsigned long baudrate = termios_p->baudrate;

#define BUFLEN 32
    char buffer[BUFLEN];

    snprintf(buffer, BUFLEN, "%lu", baudrate);
    buffer[BUFLEN - 1] = '\0';

    int baudrate_file;
    baudrate_file = openat(filedes, "baud", O_RDWR);
    if(baudrate_file == -1)
    {
        fprintf(stderr, "tcsetattr: failed to open \'baud\'\n");
        return -1;
    }

    int amt_written = write(baudrate_file, buffer, strlen(buffer));
    close(baudrate_file);
    if(amt_written < 0)
    {
        fprintf(stderr, "tcsetattr: write() to \'baud\' file failed!\n");
        return amt_written;
    }

    return 0;

#undef BUFLEN
}

static int
__tcsetattr_set_raw(int filedes, const struct termios *termios_p)
{
    char bufc = (termios_p->c_lflag & ICANON) ? '0' : '1';

    int raw_file;
    raw_file = openat(filedes, "raw", O_RDWR);
    if(raw_file == -1)
    {
        fprintf(stderr, "tcsetattr: failed to open \'raw\'\n");
        return -1;
    }

    int amt_written = write(raw_file, &bufc, 1);
    close(raw_file);
    if(amt_written < 0)
    {
        fprintf(stderr, "tcsetattr: write() to \'raw\' file failed!\n");
        return amt_written;
    }

    return 0;
}

int
tcsetattr(int filedes, int when, const struct termios *termios_p)
{
    int res;

    switch(when)
    {
    case TCSANOW:
        break;
    case TCSADRAIN:
        res = tcdrain(filedes);
        if(res)
        {
            return -1;
        }
        break;
    case TCSAFLUSH:
        res = tcflush(filedes, TCIOFLUSH);
        if(res)
        {
            return -1;
        }
        break;
    default:
        fprintf(stderr, "tcsetattr: unrecognized \'when\'=%d\n", when);
        return -1;
    }

    res = __tcsetattr_set_baudrate(filedes, termios_p);
    if(res)
    {
        errno = res;
        fprintf(stderr, "tcsetattr: __tcsetattr_set_baudrate failed!\n");
        return -1;
    }

    res = __tcsetattr_set_raw(filedes, termios_p);
    if(res)
    {
        errno = res;
        fprintf(stderr, "tcsetattr: __tcsetattr_set_raw failed!\n");
        return -1;
    }

    return 0;
}
