#ifndef __KANAWHA__ATTRIBUTE_H__
#define __KANAWHA__ATTRIBUTE_H__

#ifdef CONFIG_DISABLE_NORETURN_ATTRIBUTE
#define __noreturn
#else
#define __noreturn __attribute__((noreturn))
#endif

#endif
