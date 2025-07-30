
#ifndef __ASSEMBLER__
#define __ASSEMBLER__
#endif
#include <setjmp.h>

.global setjmp
.type setjmp,@function
setjmp:
    j .

