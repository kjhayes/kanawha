
#include <stdarg.h>
#include <stdio.h>

int
fprintf (FILE * restrict stream, const char *format, ...)
{
   int done;
   va_list arg;

   va_start (arg, format);
   done = vfprintf(stream, format, arg);
   va_end (arg);

   return done;
}

