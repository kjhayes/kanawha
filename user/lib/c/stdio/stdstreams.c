
#include <elk-libc-internal/FILE.h>
#include <stdio.h>

extern FILE __ELK_stdin;
extern FILE __ELK_stdout;
extern FILE __ELK_stderr;

FILE *stdin = &__ELK_stdin;
FILE *stdout = &__ELK_stdout;
FILE *stderr = &__ELK_stderr;
