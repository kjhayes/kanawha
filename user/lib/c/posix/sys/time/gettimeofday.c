
#include <sys/time.h>
#include <stdlib.h>
#include <time.h>

int gettimeofday(
	struct timeval *tp,
	struct timezone *tz)
{
  if (tz)
    abort ();

  tp->tv_usec = 0;
  if (time (&tp->tv_sec) == (time_t) -1)
    return -1;

  return 0;
}

