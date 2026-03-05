#ifndef __ELK_LIBC_INTERNAL__SIGEVENT_H__
#define __ELK_LIBC_INTERNAL__SIGEVENT_H__

#include <elk-libc-internal/sigval.h>

struct sigevent
{
    int sigev_notify;                            // Notification type.
    int sigev_signo;                             // Signal number.
    union sigval sigev_value;                    // Signal value.
    void (*sigev_notify_function)(union sigval); // Notification function.
    // pthread_attr_t *     sigev_notify_attributes;   //Notification
    // attributes.
};

#endif
