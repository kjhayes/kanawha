#ifndef __INIT_LOG_H__
#define __INIT_LOG_H__

#include <stdio.h>
#include <string.h>

#define LOG_BUFLEN 0x1000
extern char log_buffer[LOG_BUFLEN];

#define LOG(...) \
do {\
    snprintf(log_buffer, LOG_BUFLEN, __VA_ARGS__);\
    log_buffer[LOG_BUFLEN-1] = '\0';\
    all_term_puts(log_buffer);\
} while(0)

#define INFO(...) LOG("init: " __VA_ARGS__)
#define ERROR(...) LOG("[ERROR] init: " __VA_ARGS__)

int all_term_puts(char *msg);

#endif
