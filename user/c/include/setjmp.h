#ifndef __ELK_LIBC__SETJMP_H__
#define __ELK_LIBC__SETJMP_H__

#ifdef __x86_64__
#define __JMP_BUFSIZE 3
#define __SIGJMP_BUFSIZE 3
#endif

#if !defined(__JMP_BUFSIZE) || !defined(__SIGJMP_BUFSIZE)

// TODO

#ifndef __ASSEMBLER__
typedef void *jmp_buf[0];
typedef void *sigjmp_buf[0];
#endif

#else

#ifndef __ASSEMBLER__

typedef void *jmp_buf[__JMP_BUFSIZE];
typedef void *sigjmp_buf[__SIGJMP_BUFSIZE];

void   longjmp(jmp_buf, int);
void   siglongjmp(sigjmp_buf, int);
void  _longjmp(jmp_buf, int);

int    setjmp(jmp_buf);
int    sigsetjmp(sigjmp_buf, int);
int   _setjmp(jmp_buf);

#endif
#endif
#endif
