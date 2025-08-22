#ifndef __ELK_LIBC__INTTYPES_H__
#define __ELK_LIBC__INTTYPES_H__

#include <stdint.h>
#include <stddef.h>

// TODO (I've left all the "N" unfilled, and will only update this as needed)

#define PRId8       "d"
#define PRId16      "d"
#define PRId32      "d"
#define PRId64      "ld"
#define PRIdLEASTN  "%"
#define PRIdFASTN   "%"
#define PRIdMAX     "ld"
#define PRIdPTR     "%"
#define PRIi8       "d"
#define PRIi16      "d"
#define PRIi32      "d"
#define PRIi64      "ld"
#define PRIiLEASTN  "%"
#define PRIiFASTN   "%"
#define PRIiMAX     "%"
#define PRIiPTR     "%"
#define PRIoN       "%"
#define PRIoLEASTN  "%"
#define PRIoFASTN   "%"
#define PRIoMAX     "%"
#define PRIoPTR     "%"
#define PRIu8       "u"
#define PRIu16      "u"
#define PRIu32      "u"
#define PRIu64      "lu"
#define PRIuLEASTN  "%"
#define PRIuFASTN   "%"
#define PRIuMAX     "lu"
#define PRIuPTR     "%"
#define PRIx8       "x"
#define PRIx16      "x"
#define PRIx32      "x"
#define PRIx64      "lx"
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
