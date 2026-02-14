#ifndef __ELK_LIBC_INTERNAL__SIGVAL_H__
#define __ELK_LIBC_INTERNAL__SIGVAL_H__

union sigval {
    int    sival_int;    //Integer signal value. 
    void  *sival_ptr;    //Pointer signal value.
};

#endif
