
#include <termios.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

static int
__tcgetattr_read_baudrate(
	int filedes,
	struct termios *termios_p)
{
    int baudrate_file;
    baudrate_file = openat(filedes, "baud", O_RDONLY);
    if(baudrate_file == -1) {
	return -1;
    }
#define BUFLEN 32
    char buffer[BUFLEN];

    int amt_read = read(baudrate_file, buffer, BUFLEN);
    close(baudrate_file);

    if(amt_read == 0) {
	termios_p->baudrate = B0;
	return 0;
    }

    buffer[BUFLEN-1] = '\0';

    termios_p->baudrate = atol(buffer);
    return 0;

#undef BUFLEN
}

static int
__tcgetattr_read_raw(
	int filedes,
	struct termios *termios_p)
{
    int raw_file;
    raw_file = openat(filedes, "raw", O_RDONLY);
    if(raw_file == -1) {
	return -1;
    }

#define BUFLEN 32
    char buffer[BUFLEN];

    int amt_read = read(raw_file, buffer, BUFLEN);
    close(raw_file);

    if(amt_read == 0) {
	termios_p->c_lflag &= ~ICANON;
	return 0;
    }

    buffer[BUFLEN-1] = '\0';

    int is_raw = atoi(buffer);
    if(is_raw) {
	termios_p->c_lflag &= ~ICANON;
    } else {
	termios_p->c_lflag |= ICANON;
    }

    return 0;

#undef BUFLEN
}


static inline int
__tcgetattr_read_c_cc(
	int filedes,
	struct termios *termios_p)
{
    termios_p->c_cc[VEOF]   = (4);
    termios_p->c_cc[VEOL]   = '\n';
    termios_p->c_cc[VERASE] = '\b';
    termios_p->c_cc[VINTR]  = (3);
    termios_p->c_cc[VKILL]  = (25);
    termios_p->c_cc[VMIN]   = (1);
    termios_p->c_cc[VQUIT]  = (34);
    termios_p->c_cc[VSTART] = (21);
    termios_p->c_cc[VSTOP]  = (23);
    termios_p->c_cc[VSUSP]  = (32);
    termios_p->c_cc[VTIME]  = (0);
    termios_p->c_cc[VSWTCH] = '\0';
    return 0;
}

int
tcgetattr(
        int filedes,
        struct termios *termios_p)
{
    int res;

    memset(termios_p, 0, sizeof(struct termios));

    res = __tcgetattr_read_baudrate(filedes, termios_p);
    if(res) {
	errno = res;
	return -1;
    }

    res = __tcgetattr_read_raw(filedes, termios_p);
    if(res) {
	errno = res;
	return -1;
    }

    res = __tcgetattr_read_c_cc(filedes, termios_p);
    if(res) {
	errno = res;
	return -1;
    }

    return 0;
}

