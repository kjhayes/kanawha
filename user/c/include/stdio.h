#ifndef __ELK_LIBC__STDIO_H__
#define __ELK_LIBC__STDIO_H__

#include "elk-libc-internal/size_t.h"
#include "elk-libc-internal/ssize_t.h"
#include "elk-libc-internal/null.h"
#include "elk-libc-internal/FILE.h"
#include "elk-libc-internal/off_t.h"

#include <limits.h>

#define __need___va_list
#include <stdarg.h>

typedef struct {
    off_t __offset;
} fpos_t;

#define _IOFBF (1)
#define _IOLBF (2)
#define _IONBF (3)

#define BUFSIZ (0x1000)

#define EOF (-1)

#define FOPEN_MAX (128)

#define FILENAME_MAX (128)

#define L_tmpnam (128)

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define TMP_MAX (UINT_MAX)

extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

int fileno(FILE *stream);
int remove(const char *filename);
int rename(const char *__old, const char *__new);
FILE *tmpfile(void);
char *tmpnam(char *s);
int fclose(FILE *stream);
int fflush(FILE *stream);
FILE *fopen(const char * restrict filename, const char * restrict mode);
FILE *freopen(const char * restrict filename, const char * restrict mode, FILE * restrict stream);
FILE *fdopen(int fildes, const char *mode);
void setbuf(FILE * restrict stream, char * restrict buf);
int setvbuf(FILE * restrict stream, char * restrict buf, int mode, size_t size);
void setbuffer(FILE *stream, char *buf, size_t size);
void setlinebuf(FILE *stream);
int fprintf(FILE * restrict stream, const char * restrict format, ...);
int fscanf(FILE * restrict stream, const char * restrict format, ...);
int printf(const char * restrict format, ...);
int scanf(const char * restrict format, ...);
int snprintf(char * restrict s, size_t n, const char * restrict format, ...);
int sprintf(char * restrict s, const char * restrict format, ...);
int asprintf(char **strp, const char *restrict fmt, ...);
int dprintf(int fd, const char *format, ...);
int sscanf(const char * restrict s, const char * restrict format, ...);


#ifdef __GNUC__
#define __VALIST __gnuc_va_list
#else
#define __VALIST char*
#endif

int vfprintf(FILE * restrict stream, const char * restrict format, __VALIST arg);
int vfscanf(FILE * restrict stream, const char *restrict format, __VALIST arg);
int vprintf(const char * restrict format, __VALIST arg);
int vscanf(const char * restrict format, __VALIST arg);
int vsnprintf(char * restrict s, size_t n, const char * restrict format, __VALIST arg);
int vsprintf(char * restrict s, const char * restrict format, __VALIST arg);
int vasprintf(char **strp, const char *restrict fmt, __VALIST arg);
int vdprintf(int fd, const char *format, __VALIST ap); 
int vsscanf(const char * restrict s, const char * restrict format, __VALIST arg);

int fgetc(FILE *stream);
int getc(FILE *stream);
#define getc(__stream) fgetc(__stream)
int getchar(void);
#define getchar() getc(stdin)

char *fgets(char * restrict s, int n, FILE * restrict stream);

int fputc(int c, FILE *stream);
int putc(int c, FILE *stream);
#define putc(__c, __stream) fputc(__c, __stream)
int putchar(int c);
#define putchar(__c) putc(__c, stdout)

int fputs(const char * restrict s, FILE * restrict stream);
int puts(const char *s);
#define puts(__s) fputs(__s, stdout) 

int ungetc(int c, FILE *stream);

size_t fread(void * restrict ptr, size_t size, size_t nmemb, FILE * restrict stream);
size_t fwrite(const void * restrict ptr, size_t size, size_t nmemb, FILE * restrict stream);

int fgetpos(FILE * restrict stream, fpos_t * restrict pos);
int fseek(FILE *stream, long int offset, int whence);
int fsetpos(FILE *stream, const fpos_t *pos);
long int ftell(FILE *stream);
void rewind(FILE *stream);
void clearerr(FILE *stream);

ssize_t getline(
        char **restrict lineptr,
        size_t *restrict n,
        FILE *restrict stream);

int fseeko (FILE *fp, off_t offset, int whence);
off_t ftello(FILE *stream);

int feof(FILE *stream);
int ferror(FILE *stream);

void perror(const char *s);

void flockfile(FILE *filehandle);
int ftrylockfile(FILE *filehandle);
void funlockfile(FILE *filehandle);

// Unlocked variants
int getc_unlocked(FILE *stream);
int getchar_unlocked(void);
int putc_unlocked(int c, FILE *stream);
int putchar_unlocked(int c);
void clearerr_unlocked(FILE *stream);
int feof_unlocked(FILE *stream);
int ferror_unlocked(FILE *stream);
int fileno_unlocked(FILE *stream);
int fflush_unlocked(FILE *stream);
int fgetc_unlocked(FILE *stream);
int fputc_unlocked(int c, FILE *stream);
size_t fread_unlocked(void *ptr, size_t size, size_t n,
                      FILE *stream);
size_t fwrite_unlocked(const void *ptr, size_t size, size_t n,
                      FILE *stream);
char *fgets_unlocked(char *s, int n, FILE *stream);
int fputs_unlocked(const char *s, FILE *stream);

FILE *popen(const char *command, const char *mode);
int   pclose(FILE *);

#endif
