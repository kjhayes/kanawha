#ifndef __ELK_LIBC_POSIX__LIBGEN_H__
#define __ELK_LIBC_POSIX__LIBGEN_H__

extern char* __loc1; // (LEGACY)

char  *basename(char *);
char  *dirname(char *);
char  *regcmp(const char *, ...); // (LEGACY)
char  *regex(const char *, const char *, ...); // (LEGACY)

#endif
