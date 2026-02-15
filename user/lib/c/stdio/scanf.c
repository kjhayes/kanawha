
#include <stdarg.h>
#include <stdio.h>

int
scanf(
        const char * restrict format,
        ...)
{
   int done;
   va_list arg;

   va_start (arg, format);
   done = vfscanf(stdin, format, arg);
   va_end (arg);

   return done;
}
