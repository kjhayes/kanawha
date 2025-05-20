#ifndef __ELK_LIBC__SETJMP_H__
#define __ELK_LIBC__SETJMP_H__

#ifdef __x86_64__
#define __JMP_BUFSIZE 64
#define __SIGJMP_BUFSIZE 64
#endif

#if !defined(__JMP_BUFSIZE) || !defined(__SIGJMP_BUFSIZE)
#error "Architecture did not define __JMP_BUFSIZE or __SIGJMP_BUFSIZE!"
#endif

typedef char jmp_buf[__JMP_BUFSIZE];
typedef char sigjmp_buf[__SIGJMP_BUFSIZE];

void   longjmp(jmp_buf, int);
void   siglongjmp(sigjmp_buf, int);
void  _longjmp(jmp_buf, int);

int    setjmp(jmp_buf);
int    sigsetjmp(sigjmp_buf, int);
int   _setjmp(jmp_buf);

#endif
