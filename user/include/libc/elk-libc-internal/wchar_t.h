#ifndef __ELK_LIBC_INTERNAL__WCHAR_T_H__
#define __ELK_LIBC_INTERNAL__WCHAR_T_H__

#ifndef __WCHAR_TYPE__
#error "Elk <elk-libc-internal/wchar_t.h> needs __WCHAR_TYPE__ to be defined!"
#else
typedef __WCHAR_TYPE__ wchar_t;
#endif

#endif
