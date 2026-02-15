
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((noreturn))
void __arch_longjmp(jmp_buf buf, int ret);

__attribute__((noreturn))
void _longjmp(jmp_buf buf, int ret) {
    if(ret == 0) {
	ret = 1;
    }
    __arch_longjmp(buf, ret);

    // Should never reach here.
    fprintf(stderr, "Architecture returned from _longjmp!\n");
    abort();
}

__attribute__((noreturn))
void longjmp(jmp_buf buf, int ret)
{
    if(ret == 0) {
        ret = 1;
    }
    __arch_longjmp(buf, ret);

    // Should never reach here.
    fprintf(stderr, "Architecture returned from longjmp!\n");
    abort();
}

