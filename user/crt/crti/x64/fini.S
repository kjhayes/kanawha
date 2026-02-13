
.section .fini
.global _fini
.type _init,@function
_fini:
   push %rbp
   movq %rsp, %rbp
   /* gcc will nicely put the contents of crtbegin.o's .fini section here. */

