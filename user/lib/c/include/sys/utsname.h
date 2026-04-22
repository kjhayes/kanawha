#ifndef __ELK_LIBC_POSIX_SYS__UTSNAME_H__
#define __ELK_LIBC_POSIX_SYS__UTSNAME_H__

struct utsname
{
    char sysname[32];  // Name of this implementation of the operating system.
    char nodename[32]; // Name of this node within the communications
                       // network to which this node is attached, if any.

    char release[32]; // Current release level of this implementation.
    char version[32]; // Current version level of this release.
    char machine[32]; // Name of the hardware type on which the system is
                      // running.
};

int
uname(struct utsname *);

#endif
