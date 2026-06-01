
#ifndef __ASSEMBLER__
#define __ASSEMBLER__
#endif
#include <setjmp.h>

.global _setjmp
.global setjmp
.type _setjmp,@function
.type setjmp,@function
_setjmp:
setjmp:
    b .

