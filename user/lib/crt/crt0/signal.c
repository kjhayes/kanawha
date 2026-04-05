
#include "kanawha/sys-wrappers.h"
#include <kanawha/signal.h>
#include <stdio.h>
#include <stdlib.h>

extern void
__elk_crt__signal_handler_entry(void);

void
__elk_crt__handle_signal(void **return_addr_ptr)
{
    int res;

    unsigned long return_addr;
    unsigned long signal_no;

    res = kanawha_sys_siginfo(SIGINFO_RETURN, &return_addr);
    if(res)
    {
        printf("Unable to resolve signal return address (Exiting)\n");
        exit(res);
    }

    *return_addr_ptr = (void *)return_addr;

    res = kanawha_sys_siginfo(SIGINFO_CURRENT, &signal_no);
    if(res)
    {
        printf("Unable to resolve signal ID (Exiting)\n");
        exit(res);
    }

    printf("Received Signal (%lu)\n", signal_no);

    res = kanawha_sys_sigmod(SIGMOD_ACK, signal_no);
    if(res)
    {
        printf("Unable to acknowledge signal (Exiting)\n");
        exit(res);
    }

    switch(signal_no)
    {
    case SIGNAL_ID_MEMFAULT:
    case SIGNAL_ID_PROTFAULT:
    case SIGNAL_ID_DECODEFAULT:
    default:
        printf("Exiting due to signal! (%p)\n", (void *)return_addr);
        fflush(stdout);
        exit(-1);
    }

    fflush(stdout);
    // Return from the signal
}

int
__elk_crt__init_signal(void)
{
    int res;

    res = kanawha_sys_sigmod(SIGMOD_ENTRY,
                             (unsigned long)__elk_crt__signal_handler_entry);
    if(res)
    {
        return res;
    }

    return 0;
}
