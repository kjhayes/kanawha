#ifndef __ELK_LIBC__ASSERT_H__
#define __ELK_LIBC__ASSERT_H__

extern _Noreturn void abort(void);

#ifdef NDEBUG
#define assert(ignore) ((void)0)
#else
// TODO: Log the error message correctly
#define assert(cond) \
    do {\
        if(!(cond)) {\
            abort();\
        }\
    } while(0)
#endif

#endif
