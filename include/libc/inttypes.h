#ifndef __ELK_LIBC__INTTYPES_H__
#define __ELK_LIBC__INTTYPES_H__

#include <stdint.h>
#include <stddef.h>

// TODO (I've left all the "N" unfilled, and will only update this as needed)

#define PRIdN       "%"
#define PRIdLEASTN  "%"
#define PRIdFASTN   "%"
#define PRIdMAX     "ld"
#define PRIdPTR     "%"
#define PRIiN       "%"
#define PRIiLEASTN  "%"
#define PRIiFASTN   "%"
#define PRIiMAX     "%"
#define PRIiPTR     "%"
#define PRIoN       "%"
#define PRIoLEASTN  "%"
#define PRIoFASTN   "%"
#define PRIoMAX     "%"
#define PRIoPTR     "%"
#define PRIuN       "%"
#define PRIuLEASTN  "%"
#define PRIuFASTN   "%"
#define PRIuMAX     "lu"
#define PRIuPTR     "%"
#define PRIxN       "%"
#define PRIxLEASTN  "%"
#define PRIxFASTN   "%"
#define PRIxMAX     "%"
#define PRIxPTR     "%"
#define PRIXN       "%"
#define PRIXLEASTN  "%"
#define PRIXFASTN   "%"
#define PRIXMAX     "%"
#define PRIXPTR     "%"
#define SCNdN       "%"
#define SCNdLEASTN  "%"
#define SCNdFASTN   "%"
#define SCNdMAX     "%"
#define SCNdPTR     "%"
#define SCNiN       "%"
#define SCNiLEASTN  "%"
#define SCNiFASTN   "%"
#define SCNiMAX     "%"
#define SCNiPTR     "%"
#define SCNoN       "%"
#define SCNoLEASTN  "%"
#define SCNoFASTN   "%"
#define SCNoMAX     "%"
#define SCNoPTR     "%"
#define SCNuN       "%"
#define SCNuLEASTN  "%"
#define SCNuFASTN   "%"
#define SCNuMAX     "%"
#define SCNuPTR     "%"
#define SCNxN       "%"
#define SCNxLEASTN  "%"
#define SCNxFASTN   "%"
#define SCNxMAX     "%"
#define SCNxPTR     "%"

typedef struct {
    // TODO
} imaxdiv_t;

intmax_t  imaxabs(intmax_t);
imaxdiv_t imaxdiv(intmax_t, intmax_t);
intmax_t  strtoimax(const char *restrict, char **restrict, int);
uintmax_t strtoumax(const char *restrict, char **restrict, int);
intmax_t  wcstoimax(const wchar_t *restrict, wchar_t **restrict, int);
uintmax_t wcstoumax(const wchar_t *restrict, wchar_t **restrict, int);

#endif
