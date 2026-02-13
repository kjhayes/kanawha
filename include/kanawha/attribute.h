#ifndef __KANAWHA__ATTRIBUTE_H__
#define __KANAWHA__ATTRIBUTE_H__

#ifdef CONFIG_TOOLCHAIN_SUPPORTS_NODEREF_ATTRIBUTE
#define __noreturn __attribute__((noreturn))
#else 
#define __noreturn
#endif

#ifdef CONFIG_TOOLCHAIN_SUPPORTS_NODEREF_ATTRIBUTE
#define __noderef __attribute__((noderef))
#else
#define __noderef
#endif

#ifdef CONFIG_TOOLCHAIN_SUPPORTS_ADDRESS_SPACE_ATTRIBUTE
#define __address_space(_N) __attribute__((address_space(_N)))
#else
#define __address_space(_N)
#endif // CONFIG_TOOLCHAIN_SUPPORTS_ADDRESS_SPACE_ATTRIBUTE


#ifdef CONFIG_DISABLE_NORETURN_ATTRIBUTE
#undef __noreturn
#define __noreturn
#endif


#define __user __address_space(3)

#define __packed __attribute__((packed))
#define __maybe_unused __attribute__((unused))

#define __percpu __address_space(2) __noderef
#define __percpu_section __attribute__((section(".kpercpu")))

#endif
