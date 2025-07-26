#ifndef __KANAWHA__ATTRIBUTE_H__
#define __KANAWHA__ATTRIBUTE_H__

#ifdef CONFIG_DISABLE_NORETURN_ATTRIBUTE
#define __noreturn
#else
#define __noreturn __attribute__((noreturn))
#endif

#define __user __attribute__((address_space(3)))

#define __packed __attribute__((packed))
#define __maybe_unused __attribute__((unused))

#define __percpu_section __attribute__((section(".kpercpu")))
#define __percpu __attribute__((noderef, address_space(2)))

#define __noderef __attribute__((noderef))

#endif
