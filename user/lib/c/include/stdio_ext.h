#ifndef __ELK_LIBC__STDIO_EXT_H__
#define __ELK_LIBC__STDIO_EXT_H__

size_t
__fbufsize(FILE *stream);
size_t
__fpending(FILE *stream);
size_t
__freadahead(FILE *stream);
const char *
__freadptr(FILE *fp, size_t *sizep);
const char *
__freadptrinc(FILE *fp, size_t increment);
int
__flbf(FILE *stream);
int
__freadable(FILE *stream);
int
__fwritable(FILE *stream);
int
__freading(FILE *stream);
int
__fwriting(FILE *stream);
int
__fsetlocking(FILE *stream, int type);
void
_flushlbf(void);
void
__fpurge(FILE *stream);

#endif
