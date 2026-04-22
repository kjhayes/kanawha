#ifndef __ELK_LIBC_POSIX_NET__IF_H__
#define __ELK_LIBC_POSIX_NET__IF_H__

#define IF_NAMESIZE 32

struct if_nameindex
{
    unsigned if_index; // Numeric index of the interface.
    char *if_name;     // Null-terminated name of the interface.
};

unsigned
if_nametoindex(const char *);
char *
if_indextoname(unsigned, char *);
struct if_nameindex *
if_nameindex(void);
void
if_freenameindex(struct if_nameindex *);

#endif
