
#include <kanawha/net/ip.h>

int
dump_ipv4_addr(
        printk_f *printer,
        struct ipv4_addr *addr
        )
{
    (*printer)("%d.%d.%d.%d",
            (u_t)addr->data[0],
            (u_t)addr->data[1],
            (u_t)addr->data[2],
            (u_t)addr->data[3]
            );
    return 0;
}

int
dump_ipv6_addr(
        printk_f *printer,
        struct ipv6_addr *addr
        )
{
    (*printer)("%x:%x:%x:%x:%x:%x:%x:%x",
            (u_t)betoh16(addr->data[0]),
            (u_t)betoh16(addr->data[1]),
            (u_t)betoh16(addr->data[2]),
            (u_t)betoh16(addr->data[3]),
            (u_t)betoh16(addr->data[4]),
            (u_t)betoh16(addr->data[5]),
            (u_t)betoh16(addr->data[6]),
            (u_t)betoh16(addr->data[7])
            );
    return 0;
}

