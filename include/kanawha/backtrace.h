#ifndef __KANAWHA__BACKTRACE_H__
#define __KANAWHA__BACKTRACE_H__

// Routines/Macros for function reflection
// Depending on compiler toolchain support,
// any of these routines *may* return NULL
// if the current function-address, frame, 
// return-address, etc. cannot be determined.

#include <kanawha/stddef.h>
#include <kanawha/attribute.h>

// TODO: Actually add checks that these builtins exist,
// this may cause problems on non-GCC toolchains
#define current_return_address() ((void*)__builtin_return_address(0))
#define current_frame_address() ((void*)__builtin_frame_address(0))

#ifndef current_return_address
#define current_return_address() (NULL)
#endif
#ifndef current_frame_address
#define current_frame_address() (NULL)
#endif

#endif
