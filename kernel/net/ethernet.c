
#include <kanawha/net/ethernet.h>

int dump_eth_mac_addr(printk_f *printer, struct eth_mac_addr *addr)
{
    (*printer)("%x:%x:%x:%x:%x:%x",
            addr[0],
            addr[1],
            addr[2],
            addr[3],
            addr[4],
            addr[5]
            );
    return 0;
}

