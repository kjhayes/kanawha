#ifndef __LENSD__UTIL_H__
#define __LENSD__UTIL_H__

#include <lens/lens.h>
#include <elk/list.h>
#include <stdio.h>
#include <unistd.h>
#include <threads.h>


extern int lensd_running;
extern int lensd_verbose;

#define INFO(FMT, ...)\
    if(lensd_verbose) {\
        printf("lens: " FMT, ##__VA_ARGS__);\
    }
#define ERROR(FMT, ...)\
    fprintf(stderr, "lens: [ERROR] " FMT, ##__VA_ARGS__);\

int
foreach_in_dir(
        const char *dir_path,
        int(*callback)(const char *path));

#endif
