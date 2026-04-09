#ifndef __ELK_POSIX__TERMIOS_H__
#define __ELK_POSIX__TERMIOS_H__

#include <sys/types.h>

typedef int cc_t;
typedef int speed_t;
typedef int tcflag_t;

struct termios;
struct winsize;

// c_iflag Macros
#define BRKINT (1ULL<<0) //Signal interrupt on break. 
#define ICRNL  (1ULL<<1) //Map CR to NL on input. 
#define IGNBRK (1ULL<<2) //Ignore break condition. 
#define IGNCR  (1ULL<<3) //Ignore CR 
#define IGNPAR (1ULL<<4) //Ignore characters with parity errors. 
#define INLCR  (1ULL<<5) //Map NL to CR on input. 
#define INPCK  (1ULL<<6) //Enable input parity check. 
#define ISTRIP (1ULL<<7) //Strip character 
#define IUCLC  (1ULL<<8) //Map upper-case to lower-case on input (LEGACY). 
#define IXANY  (1ULL<<9) //Enable any character to restart output. 
#define IXOFF  (1ULL<<10) //Enable start/stop input control. 
#define IXON   (1ULL<<11) //Enable start/stop output control. 
#define PARMRK (1ULL<<12) //Mark parity errors.

// c_oflag Macros
#define OPOST       (1ULL<<0)  //Post-process output 
#define OLCUC       (1ULL<<1)  //Map lower-case to upper-case on output (LEGACY). 
#define ONLCR       (1ULL<<2)  //Map NL to CR-NL on output. 
#define OCRNL       (1ULL<<3)  //Map CR to NL on output. 
#define ONOCR       (1ULL<<4)  //No CR output at column 0. 
#define ONLRET      (1ULL<<5)  //NL performs CR function. 
#define OFILL       (1ULL<<6)  //Use fill characters for delay. 
#define NLDLY       (0b1<<7)
#define NL0         (0b0<<7)  //Newline character type 0. 
#define NL1         (0b1<<7)  //Newline character type 1. 
#define CRDLY       (0b11<<8) 
#define CR0         (0b00<<8) //Carriage-return delay type 0. 
#define CR1         (0b01<<8) //Carriage-return delay type 1. 
#define CR2         (0b10<<8) //Carriage-return delay type 2. 
#define CR3         (0b11<<8) //Carriage-return delay type 3. 
#define TABDLY      (0b11<<10) 
#define TAB0        (0b00<<10) //Horizontal-tab delay type 0. 
#define TAB1        (0b01<<10) //Horizontal-tab delay type 0. 
#define TAB2        (0b10<<10) //Horizontal-tab delay type 0. 
#define TAB3        (0b11<<10) //Horizontal-tab delay type 0. 
#define BSDLY       (0b1<<12)
#define BS0         (0b0<<12)  //Backspace-delay type 0. 
#define BS1         (0b1<<12)  //Backspace-delay type 1. 
#define VTDLY       (0b1<<13) 
#define VT0         (0b0<<13) //Vertical-tab delay type 0. 
#define VT1         (0b1<<13) //Vertical-tab delay type 1. 
#define FFDLY       (0b1<<14)
#define FF0         (0b0<<14) //Form-feed delay type 0. 
#define FF1         (0b1<<14) //Form-feed delay type 1. 

// c_cflag Macros
#define CSIZE (0b11)
#define CS5 (0b00)
#define CS6 (0b01)
#define CS7 (0b10)
#define CS8 (0b11)
#define CSTOPB (1ULL<<2) //Send two stop bits, else one.
#define CREAD  (1ULL<<3) //Enable receiver.
#define PARENB (1ULL<<4) //Parity enable.
#define PARODD (1ULL<<5) //Odd parity, else even.
#define HUPCL  (1ULL<<6) //Hang up on last close.
#define CLOCAL (1ULL<<7) //Ignore modem status lines. 

// c_lflag Macros
#define ECHO    (1ULL<<1)
#define ECHOE   (1ULL<<2)
#define ECHOK   (1ULL<<3)
#define ECHONL  (1ULL<<4)
#define ICANON  (1ULL<<5)
#define IEXTEN  (1ULL<<6)
#define ISIG    (1ULL<<7)
#define NOFLSH  (1ULL<<8)
#define TOSTOP  (1ULL<<9)
#define XCASE   (1ULL<<10)
#define FLUSHO  (1ULL<<11)
#define PENDIN  (1ULL<<12)
#define ECHOCTL (1ULL<<13)
#define ECHOPRT (1ULL<<14)
#define ECHOKE  (1ULL<<15)
#define DEFECHO (1ULL<<16)

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

#define B0 (0UL)
#define B50 (50UL)
#define B75 (75UL)
#define B110 (110UL)
#define B134 (134UL)
#define B150 (150UL)
#define B200 (200UL)
#define B300 (300UL)
#define B600 (600UL)
#define B1200 (1200UL)
#define B1800 (1800UL)
#define B2400 (2400UL)
#define B4800 (4800UL)
#define B9600 (9600UL)
#define B19200 (19200UL)
#define B38400 (38400UL)
#define B57600 (57600UL)
#define B115200 (115200UL)
#define B230400 (230400UL)
#define B460800 (460800UL)
#define B500000 (500000UL)
#define B576000 (576000UL)
#define B921600 (921600UL)
#define B1000000 (1000000UL)
#define B1152000 (1152000UL)
#define B1500000 (1500000UL)
#define B2000000 (2000000UL)
#define B76800 (76800UL)
#define B153600 (153600UL)
#define B307200 (307200UL)
#define B614400 (614400UL)
#define B2500000 (2500000UL)
#define B3000000 (3000000UL)
#define B3500000 (3500000UL)
#define B4000000 (4000000UL)

#define VEOF   (0)  // EOF character
#define VEOL   (1)  // EOL character
#define VERASE (2)  // ERASE character
#define VINTR  (3)  // INTR character (Ctrl-C)
#define VKILL  (4)  // KILL character
#define VMIN   (5)  // MIN value
#define VQUIT  (6)  // QUIT character
#define VSTART (7)  // START character
#define VSTOP  (8)  // STOP character (Ctrl-S)
#define VSUSP  (9)  // SUSP character (Ctrl-Z)
#define VTIME  (10) // TIME value
#define VSWTCH (11) // SWITCH character
#define NCCS (12)

#define TIOCGWINSZ (1)
#define TIOCSWINSZ (2)

struct termios {
    unsigned long baudrate;

    cc_t      c_cc[NCCS];  // Control characters.

    tcflag_t  c_iflag;     // Input modes. 
    tcflag_t  c_oflag;     // Output modes. 
    tcflag_t  c_cflag;     // Control modes. 
    tcflag_t  c_lflag;     // Local modes. 
};

struct winsize {
    unsigned short ws_row;
    unsigned short ws_col;
    unsigned short ws_xpixel;  /* unused */
    unsigned short ws_ypixel;  /* unused */
};

#endif
