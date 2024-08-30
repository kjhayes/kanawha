#ifndef __KANAWHA__STRING_H__
#define __KANAWHA__STRING_H__

#include <kanawha/stdint.h>

void *memset(void *str, int c, size_t n);
void *memcpy(void *dest, const void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);

size_t strlen(const char *str);
char *strcpy(char *dst, const char *src);
char *strncpy(char *dst, const char *src, size_t n);
int strcmp(const char *lhs, const char *rhs);

// Duplicates the string using kmalloc
char *kstrdup(const char *str);

#endif
