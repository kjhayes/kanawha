#ifndef __ELK_LIBC_POSIX__REGEX_H__
#define __ELK_LIBC_POSIX__REGEX_H__

#include <sys/types.h>

typedef struct
{
    size_t    re_nsub; // number of parenthesised subexpressions
} regex_t;

typedef ssize_t regoff_t;

typedef struct
{
    regoff_t    rm_so; // byte offset from start of string
                       // to start of substring
    regoff_t    rm_eo; // byte offset from start of string
                       // of the first character after the end of substring
} regmatch_t;

// cflags
#define REG_EXTENDED (1ULL<<0)
#define REG_ICASE    (1ULL<<1)
#define REG_NOSUB    (1ULL<<2)
#define REG_NEWLINE  (1ULL<<3)

// eflags
#define REG_NOTBOL (1ULL<<0)
#define REG_NOTEOL (1ULL<<1)

#define REG_NOMATCH  (1)
#define REG_BADPAT   (2)
#define REG_ECOLLATE (3)
#define REG_ECTYPE   (4)
#define REG_EESCAPE  (5)
#define REG_ESUBREG  (6)
#define REG_EBRACK   (7)
#define REG_EPAREN   (8)
#define REG_EBRACE   (9)
#define REG_BADBR    (10)
#define REG_ERANGE   (11)
#define REG_ESPACE   (12)
#define REG_BADRPT   (13)
#define REG_ENOSYS   (14)

int    regcomp(regex_t *, const char *, int);
int    regexec(const regex_t *, const char *, size_t, regmatch_t[], int);
size_t regerror(int, const regex_t *, char *, size_t);
void   regfree(regex_t *);

#endif
