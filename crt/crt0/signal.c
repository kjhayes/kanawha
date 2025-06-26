
#include <stdio.h>
#include <stdlib.h>
#include "kanawha/sys-wrappers.h"

extern void __elk_crt__default_signal_handler_entry(void);

void
__elk_crt__default_signal_handler(
        unsigned long signal_no
        )
{
    fprintf(stdout, "Received Signal (%ld): Exiting...\n",
            signal_no);
    fflush(stdout);
    exit(-1);
}

int
__elk_crt__init_signal(void)
{
    int res;

    res = kanawha_sys_sigroute(__elk_crt__default_signal_handler_entry);
    if(res) {
        return res;
    }

    return 0;
}

