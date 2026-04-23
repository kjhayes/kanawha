#ifndef __KANAWHA__SOCK_MSG_H__
#define __KANAWHA__SOCK_MSG_H__

#include <stdint.h>

struct sock_msg {
    uint8_t type;
    uint8_t index;
    uint16_t length;
    uint8_t data[];
};

#define SOCK_MSG_ID_LIMIT (1UL<<(sizeof(((struct sock_msg*)0)->type)*8))

#endif
