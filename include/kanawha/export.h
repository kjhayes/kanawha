#ifndef __KANAWHA__EXPORT_H__
#define __KANAWHA__EXPORT_H__

#include <kanawha/symbol.h>

#define EXPORT_SYMBOL(SYMBOL)\
    static struct ksymbol \
    __attribute__((section(".ksymtab")))\
    __attribute__((used))\
    __ksymtab_ ## SYMBOL = {\
        .symbol = #SYMBOL,\
        .value = (uintptr_t)(void*)&SYMBOL,\
    }

#endif
