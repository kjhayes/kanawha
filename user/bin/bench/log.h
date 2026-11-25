#ifndef __BENCH__LOOP_H__
#define __BENCH__LOOP_H__

#include <stdio.h>

#define INFO(fmt, ...)\
    fprintf(stdout, fmt, ##__VA_ARGS__)
#define WARN(fmt, ...)\
    fprintf(stderr, fmt, ##__VA_ARGS__)
#define ERROR(fmt, ...)\
    fprintf(stderr, fmt, ##__VA_ARGS__)

#endif
