#ifndef __ELK_LIBC__STDLIB_H__
#define __ELK_LIBC__STDLIB_H__

#include "elk-libc-internal/size_t.h"
#include "elk-libc-internal/wchar_t.h"

double atof(const char *nptr);
int atoi(const char *nptr);
long int atol(const char *nptr);
long long int atoll(const char *nptr);

double strtod(
        const char * restrict nptr,
        char ** restrict endptr);
float strtof(
        const char * restrict nptr,
        char ** restrict endptr);
long double strtold(
        const char * restrict nptr,
        char ** restrict endptr);

long int strtol(
        const char * restrict nptr,
        char ** restrict endptr,
        int base);
long long int strtoll(
        const char * restrict nptr,
        char ** restrict endptr,
        int base);
unsigned long int strtoul(
        const char * restrict nptr,
        char ** restrict endptr,
        int base);
unsigned long long int strtoull(
        const char * restrict nptr,
        char ** restrict endptr,
        int base);

#define RAND_MAX ((int)0x7FFFFFFF)

int rand(void);
void srand(unsigned int seed);

void *aligned_alloc(size_t alignment, size_t size);
void *calloc(size_t nmemb, size_t size);
void free(void *ptr);
void *malloc(size_t size);
void *realloc(void *ptr, size_t size);

_Noreturn void abort(void);

#define EXIT_SUCCESS (0)
#define EXIT_FAILURE (-1)

int atexit(void (*func)(void));
int at_quick_exit(void (*func)(void));
_Noreturn void exit(int status);
_Noreturn void _Exit(int status);
char *getenv(const char *name);
int setenv(const char *envname, const char *envval, int overwrite);
_Noreturn void quick_exit(int status);
int system(const char *string);

void *bsearch(
        const void *key,
        const void *base,
        size_t nmemb,
        size_t size,
        int (*compar)(const void *, const void *));

void qsort(
        void *base,
        size_t nmemb,
        size_t size,
        int (*compar)(const void *, const void *));

int abs(int j);
long int labs(long int j);
long long int llabs(long long int j);

typedef struct {
  int quot;
  int rem;
} div_t;

typedef struct {
  long quot;
  long rem;
} ldiv_t;

typedef struct {
  long long quot;
  long long rem;
} lldiv_t;

div_t div(int numer, int denom);
ldiv_t ldiv(long int numer, long int denom);
lldiv_t lldiv(long long int numer, long long int denom);

#define MB_CUR_MAX ((size_t)1)

int mblen(const char *s, size_t n);

int mbtowc(
        wchar_t * restrict pwc,
        const char * restrict s,
        size_t n);

int wctomb(char *s, wchar_t wc);

size_t mbstowcs(
        wchar_t * restrict pwcs,
        const char * restrict s,
        size_t n);

size_t wcstombs(
        char * restrict s,
        const wchar_t * restrict pwcs,
        size_t n);

#endif
