#ifndef __ELK_LIBC__WCHAR_H__
#define __ELK_LIBC__WCHAR_H__

// Technically we can't just include these files to be conformant
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

typedef int wint_t;

#define WEOF ((wint_t)0)

#endif
