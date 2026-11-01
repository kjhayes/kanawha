#ifndef __ELK_LIBC__INTERNAL__ATTRIBUTE_H__
#define __ELK_LIBC__INTERNAL__ATTRIBUTE_H__

#define __elk_libc__returns_twice \
    __attribute__((returns_twice))

#define __elk_libc__noreturn \
    __attribute__((noreturn))

#endif
