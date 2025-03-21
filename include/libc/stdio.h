#ifndef __ELK_LIBC__STDIO_H__
#define __ELK_LIBC__STDIO_H__

#include "elk-libc-internal/size_t.h"
#include "elk-libc-internal/null.h"
#include "elk-libc-internal/FILE.h"

#define __need___va_list
#include <stdarg.h>


typedef unsigned long fpos_t;

#define _IOFBF (1)
#define _IOLBF (2)
#define _IONBF (3)

#define BUFSIZ (0x1000)

#define EOF (-1)

#define FOPEN_MAX (128)

#define FILENAME_MAX (128)

#define L_tmpname (128)

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define TMP_MAX (128)

extern FILE *stdout;
extern FILE *stdin;
extern FILE *stderr;

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
int fprintf(FILE * restrict stream, const char * restrict format, ...);
int fscanf(FILE * restrict stream, const char * restrict format, ...);
int printf(const char * restrict format, ...);
int scanf(const char * restrict format, ...);
int snprintf(char * restrict s, size_t n, const char * restrict format, ...);
int sprintf(char * restrict s, const char * restrict format, ...);
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

int feof(FILE *stream);
int ferror(FILE *stream);

void perror(const char *s);

#endif
