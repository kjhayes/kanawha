#ifndef __ELK_POSIX__TERMIOS_H__
#define __ELK_POSIX__TERMIOS_H__

#include <sys/types.h>

typedef int cc_t;
typedef int speed_t;
typedef int tcflag_t;

#define NCCS 0

struct termios {
    tcflag_t  c_iflag;     // Input modes. 
    tcflag_t  c_oflag;     // Output modes. 
    tcflag_t  c_cflag;     // Control modes. 
    tcflag_t  c_lflag;     // Local modes. 
    cc_t      c_cc[NCCS];  // Control characters.
};

// c_lflag Macros
#define ECHO   (1)
#define ECHOE  (2)
#define ECHOK  (3)
#define ECHONL (4)
#define ICANON (5)
#define IEXTEN (6)
#define ISIG   (7)
#define NOFLSH (8)
#define TOSTOP (9)
#define XCASE  (10)

// tcsetattr Macros
#define TCSANOW   (1)
#define TCSADRAIN (2)
#define TCSAFLUSH (3)

// tcflush Macros
#define TCIFLUSH  (1)
#define TCIOFLUSH (2)
#define TCOFLUSH  (3)

// tcflow Macros
#define TCIOFF (1)
#define TCION  (2)
#define TCOOFF (3)
#define TCOON  (4)

speed_t cfgetispeed(const struct termios *);
speed_t cfgetospeed(const struct termios *);
int     cfsetispeed(struct termios *, speed_t);
int     cfsetospeed(struct termios *, speed_t);
int     tcdrain(int);
int     tcflow(int, int);
int     tcflush(int, int);
int     tcgetattr(int, struct termios *);
pid_t   tcgetsid(int);
int     tcsendbreak(int, int);
int     tcsetattr(int, int, const struct termios *);

#endif
