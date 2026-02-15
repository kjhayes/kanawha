
#include <termios.h>
#include <unistd.h>

int
isatty (int fd)
{
  struct termios term;
  return tcgetattr(fd, &term) == 0;
}

