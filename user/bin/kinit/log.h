#ifndef __KINIT__LOG_H__
#define __KINIT__LOG_H__

#include <stdio.h>

extern int kinit_verbose;

#define MSG(fmt, ...) MSG_RAW("kinit: " fmt, ##__VA_ARGS__)

#define MSG_RAW(fmt, ...)\
    printf(fmt, ##__VA_ARGS__)

#define INFO(fmt, ...) INFO_RAW("kinit: " fmt, ##__VA_ARGS__)

#define INFO_RAW(fmt, ...)\
    if(kinit_verbose) {\
        printf(fmt, ##__VA_ARGS__);\
    }

#define ERROR(fmt, ...) ERROR_RAW("[ERROR] kinit: " fmt, ##__VA_ARGS__)

#define ERROR_RAW(fmt, ...)\
    fprintf(stderr, fmt, ##__VA_ARGS__)

#endif
