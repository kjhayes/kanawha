
#include <fcntl.h>
#include <kanawha/dir.h>
#include <kanawha/errno.h>
#include <kanawha/file.h>
#include <kanawha/mount.h>
#include <kanawha/sys-wrappers.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "daemon.h"
#include "log.h"
#include "root.h"

int
setstdin(const char *path)
{
    int file = open(path, O_RDONLY);
    dup2(file, 0);
}
int
setstdout(const char *path)
{
    int file = open(path, O_WRONLY);
    dup2(file, 1);
}
int
setstderr(const char *path)
{
    int file = open(path, O_WRONLY);
    dup2(file, 2);
}

static const char *randd_args[] = {"randd", NULL};
static struct daemon_socket randd_sockets[] = {{
    .env = "RANDD_SOCKET",
}};
static struct daemon randd = {
    .command = "/sys/initrd/randd",
    .args = randd_args,
    .status = DAEMON_UNINIT,
    .restart_on_exit = 1,
    .num_sockets = 1,
    .sockets = randd_sockets,
};

static const char *windd_args[] = {"windd",
    "/dev/fb/vga", "4",
    "/dev/input/ps2-kbd-0",
    "/dev/input/ps2-mouse-0"
};
static struct daemon_socket windd_sockets[] = {{
    .env = "WINDD_SOCKET",
}};
static struct daemon windd = {
    .command = "/sys/initrd/windd",
    .args = windd_args,
    .status = DAEMON_UNINIT,
    .restart_on_exit = 1,
    .num_sockets = 1,
    .sockets = windd_sockets,
};

static const char *sh_args[] = {"sh", "/sys/initrd/aidedinit.sh", NULL};
static struct daemon sh = {
    .command = "/sys/initrd/sh",
    .args = sh_args,
    .restart_on_exit = 1,
    .status = DAEMON_UNINIT,
    .num_sockets = 0,
};

static struct daemon *daemons[] = {
    &randd,
    &windd,
    &sh,
    NULL,
};

int
main(int argc, const char **argv)
{
    int res;

    res = setup_root_fs();
    if(res)
    {
        return res;
    }

    setstdin("/dev/term/COM1");
    setstdout("/dev/term/COM1");
    setstderr("/dev/term/COM1");

    printf_enabled = 1;

    printf("-- Kanawha OS \"init\" --\n");

    setenv("PATH", "/bin;/usr/bin;/sys/initrd;/sys/initrd/usr/bin;", 1);

    struct daemon **d = daemons;
    while(*d)
    {
        start_daemon(*d);
        d++;
    }

    while(1)
    {
        int daemon_exitcode;
        res = waitpid(-1, &daemon_exitcode, 0);
        if(res <= 0)
        {
            INFO("waitpid returned early? res=%d\n", res);
            continue;
        }
        struct daemon **d = daemons;
        INFO("d = %p\n", d);
        INFO("*d = %p\n", *d);
        int found = 0;
        while(*d)
        {
            INFO("Checking Daemon...\n");
            struct daemon *daemon = *d;
            if(daemon->pid == res)
            {
                // This is the one
                found = 1;
                if(daemon->restart_on_exit)
                {
                    res = start_daemon(daemon);
                    if(res)
                    {
                        ERROR("Failed to restart daemon: "
                              "%s!\n",
                              daemon->command);
                    }
                }
                break;
            }
            d++;
        }
        if(!found)
        {
            ERROR("waitpid returned PID(%d) which does not "
                  "correspond to a "
                  "running daemon?\n",
                  res);
        }
    }

    ERROR("returned from main loop!\n");
    return -EINVAL;
}
