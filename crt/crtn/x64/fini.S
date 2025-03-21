
.section .fini
   /* gcc will nicely put the contents of crtend.o's .fini section here. */
   popq %rbp
   ret

