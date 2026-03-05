#ifndef __ELK_LIBC__STRING_H__
#define __ELK_LIBC__STRING_H__

#include "elk-libc-internal/null.h"
#include "elk-libc-internal/size_t.h"

void *
memcpy(void *restrict s1, const void *restrict s2, size_t n);

void *
memmove(void *s1, const void *s2, size_t n);

char *
strcpy(char *restrict s1, const char *restrict s2);

char *
strncpy(char *restrict s1, const char *restrict s2, size_t n);

char *
strcat(char *restrict s1, const char *restrict s2);

char *
strncat(char *restrict s1, const char *restrict s2, size_t n);

int
memcmp(const void *s1, const void *s2, size_t n);

int
strcmp(const char *s1, const char *s2);

int
strcoll(const char *s1, const char *s2);

int
strncmp(const char *s1, const char *s2, size_t n);

size_t
strxfrm(char *restrict s1, const char *restrict s2, size_t n);

void *
memchr(const void *s, int c, size_t n);

void *
memrchr(const void *s, int c, size_t n);

char *
strchr(const char *s, int c);

size_t
strcspn(const char *s1, const char *s2);

char *
strpbrk(const char *s1, const char *s2);

/*
 * Returns a pointer to the last occurrence of a character in the string.
 *
 * Returns NULL if the character is not found.
 */
char *
strrchr(const char *s, int c);

size_t
strspn(const char *s1, const char *s2);

char *
strstr(const char *s1, const char *s2);

char *
strtok(char *restrict s1, const char *restrict s2);

char *
strtok_r(char *str, const char *delim, char **saveptr);

void *
memset(void *s, int c, size_t n);

char *
strerror(int errnum);

size_t
strlen(const char *s);

size_t
strnlen(const char *s, size_t maxlen);

char *
strdup(const char *string);
char *
strndup(const char *s, size_t n);

// Not strictly standards conforming
// but often lumped into string.h from BSD strings.h
int
strcasecmp(const char *, const char *);
int
strncasecmp(const char *, const char *, size_t);

int
strverscmp(const char *s1, const char *s2);

char *
stpcpy(char *dest, const char *src);
char *
stpncpy(char *restrict s1, const char *restrict s2, size_t n);

char *
strchrnul(const char *s, int c);

void *
mempcpy(void *dest, const void *src, size_t n);

char *
strsignal(int sig);
const char *
sigdescr_np(int sig);
const char *
sigabbrev_np(int sig);

#endif
