
#include <kanawha/net/ethernet.h>
#include <kanawha/types.h>

int dump_eth_mac_addr(printk_f *printer, struct eth_mac_addr *addr)
{
    (*printer)("%x:%x:%x:%x:%x:%x",
            (u_t)addr->data[0],
            (u_t)addr->data[1],
            (u_t)addr->data[2],
            (u_t)addr->data[3],
            (u_t)addr->data[4],
            (u_t)addr->data[5]
            );
    return 0;
}

