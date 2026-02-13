
#include <stdio.h>
#include <elk-libc-internal/__sFILE.h>

extern struct __sFILE __ELK_stdin;
extern struct __sFILE __ELK_stdout;
extern struct __sFILE __ELK_stderr;

FILE *stdin = &__ELK_stdin;
FILE *stdout = &__ELK_stdout;
FILE *stderr = &__ELK_stderr;

