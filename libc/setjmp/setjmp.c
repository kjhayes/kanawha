
#include <setjmp.h>

__attribute__((noreturn))
int __arch_setjmp(jmp_buf buf);

int setjmp(jmp_buf buf)
{
    __arch_setjmp(buf);
    return 0;
}

