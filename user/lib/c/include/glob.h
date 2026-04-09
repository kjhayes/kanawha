#ifndef __ELK_LIBC_POSIX__GLOB_H__
#define __ELK_LIBC_POSIX__GLOB_H__

#include <stdint.h>
#include <stddef.h>

typedef struct {
    size_t   gl_pathc; // Count of paths matched by pattern. 
    char   **gl_pathv; // Pointer to a list of matched pathnames. 
    size_t   gl_offs;  // Slots to reserve at the beginning of gl_pathv. 
} glob_t;


#define GLOB_APPEND    (1ULL<<0)
#define GLOB_DOOFFS    (1ULL<<1) 
#define GLOB_ERR       (1ULL<<2)
#define GLOB_MARK      (1ULL<<3)
#define GLOB_NOCHECK   (1ULL<<4)
#define GLOB_NOESCAPE  (1ULL<<5)
#define GLOB_NOSORT    (1ULL<<6)

#define GLOB_ABORTED  (-1)
#define GLOB_NOMATCH  (-2)
#define GLOB_NOSPACE  (-3)
#define GLOB_NOSYS    (-4)

int  glob(const char *restrict, int, int (*)(const char *, int),
         glob_t *restrict);
void globfree(glob_t *);

#endif
