
.section .init
.type _init,@function
.global _init
_init:
   push %rbp
   movq %rsp, %rbp
   /* gcc will nicely put the contents of crtbegin.o's .init section here. */


