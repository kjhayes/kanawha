
#ifndef __ASSEMBLER__
#define __ASSEMBLER__
#endif
#include <setjmp.h>

.global _setjmp
.type _setjmp,@function
.global setjmp
.type setjmp,@function
_setjmp:
setjmp:
    b .

