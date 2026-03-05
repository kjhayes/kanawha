#ifndef __KANAWHA__STRING_H__
#define __KANAWHA__STRING_H__

#include <kanawha/pointer.h>
#include <kanawha/types.h>

void *
memset(void *str, int c, size_t n);
void *
memcpy(void *dest, const void *src, size_t n);
void *
memmove(void *dest, const void *src, size_t n);
int
memcmp(const void *lhs, const void *rhs, size_t n);

size_t
strlen(const char *str);
size_t
strnlen(const char *str, size_t maxlen);
char *
strcpy(char *dst, const char *src);
char *
strncpy(char *dst, const char *src, size_t n);
int
strcmp(const char *lhs, const char *rhs);
int
strncmp(const char *lhs, const char *rhs, size_t n);
int
strcasecmp(const char *lhs, const char *rhs, size_t n);
int
strncasecmp(const char *lhs, const char *rhs, size_t n);

// Duplicates the string using kmalloc
char *
kstrdup(const char *str);

// Copying to/from/around physical memory
void
memcpy_pp(void __phys *dest, void __phys *src, size_t n);
void
memcpy_vp(void __phys *dest, void *src, size_t n);
void
memcpy_pv(void *dest, void __phys *src, size_t n);

// Memset on physical memory
void
memset_p(void __phys *str, int c, size_t n);

#endif
