#ifndef __ANSITERM__ANSITERM_H__
#define __ANSITERM__ANSITERM_H__

#include <stdio.h>

int
ansiterm_get_cursor(
        unsigned long *x,
        unsigned long *y);

int
ansiterm_set_cursor(
        unsigned long x,
        unsigned long y);

int
ansiterm_get_dimensions(
        unsigned long *width,
        unsigned long *height);

#endif
