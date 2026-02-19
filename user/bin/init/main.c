
#include <kanawha/sys-wrappers.h>
#include <kanawha/dir.h>
#include <kanawha/file.h>
#include <kanawha/errno.h>
#include <kanawha/mount.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "root.h"
#include "daemon.h"

int
setstdin(const char *path)
{
    int file = open(path, O_RDONLY);
    dup2(file, 0);
    close(file);
}
int
setstdout(const char *path)
{
    int file = open(path, O_WRONLY);
    dup2(file, 1);
    close(file);
}
int
setstderr(const char *path)
{
    int file = open(path, O_WRONLY);
    dup2(file, 2);
    close(file);
}

int main(int argc, const char **argv)
{
    int res;

    res = setup_root_fs();
    if(res) {return res;}

    setstdin("/dev/term/COM1");
    setstdout("/dev/term/COM1");
    setstderr("/dev/term/COM1");
  
    printf("-- Kanawha OS \"init\" --\n");

    setenv("PATH", "/bin;/usr/bin;/sys/initrd;/sys/initrd/usr/bin;", 1);

    static const char *randd_args[] = {
        "randd",
        NULL
    };
    static struct daemon_socket randd_sockets[] = {
        {
            .env = "RANDD_SOCKET",
        }
    };
    static struct daemon randd = {
        .command = "/sys/initrd/randd",
        .args = randd_args,
        .status = DAEMON_UNINIT,
        .num_sockets = 1,
        .sockets = randd_sockets,
    };

    start_daemon(&randd);

    static const char *sh_args[] = {
        "sh",
        "/sys/initrd/aidedinit.sh",
        NULL
    };
    static struct daemon sh = {
        .command = "/sys/initrd/sh",
        .args = sh_args,
        .status = DAEMON_UNINIT,
        .num_sockets = 0,
    };

    start_daemon(&sh);

    while(1) {
        sleep(10);
    }

    ERROR("returned from main loop!\n");
    return -EINVAL;
}

