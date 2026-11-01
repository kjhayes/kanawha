#ifndef __ELK_LIBC__SETJMP_H__
#define __ELK_LIBC__SETJMP_H__

#include <elk-libc-internal/attribute.h>

#ifdef __x86_64__
#define __JMP_BUFSIZE (0x40)
#define __SIGJMP_BUFSIZE (0x40)
#endif

#if !defined(__JMP_BUFSIZE)
#define __JMP_BUFSIZE 0
#endif
#if !defined(__SIGJMP_BUFSIZE)
#define __SIGJMP_BUFSIZE 0
#endif

#ifndef __ASSEMBLER__

typedef unsigned char jmp_buf[__JMP_BUFSIZE];
typedef unsigned char sigjmp_buf[__SIGJMP_BUFSIZE];

__elk_libc__noreturn
void
longjmp(jmp_buf, int);

__elk_libc__noreturn
void
siglongjmp(sigjmp_buf, int);

__elk_libc__noreturn
void
_longjmp(jmp_buf, int);

__elk_libc__returns_twice
int
setjmp(jmp_buf);

__elk_libc__returns_twice
int
sigsetjmp(sigjmp_buf, int);

__elk_libc__returns_twice
int
_setjmp(jmp_buf);

#endif
#endif
