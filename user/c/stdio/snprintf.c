
#include <stdarg.h>
#include <stdio.h>

int
snprintf(char * restrict s, size_t n, const char * restrict format, ...)
{
   va_list arg;
   int done;

   va_start (arg, format);
   done = vsnprintf (s, n, format, arg);
   va_end (arg);

   return done;
}

