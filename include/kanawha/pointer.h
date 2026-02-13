#ifndef __KANAWHA__ASPACE_H__
#define __KANAWHA__ASPACE_H__

#ifdef CONFIG_TOOLCHAIN_SUPPORTS_ADDRESS_SPACE_ATTRIBUTE
#define __phys __attribute__((address_space(4)))
#else
#define __phys
#endif

#endif
