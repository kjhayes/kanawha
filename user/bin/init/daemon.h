#ifndef __DAEMON_H__
#define __DAEMON_H__

#include <kanawha/process.h>

struct daemon
{
    const char *command;
    const char **args;

    pid_t pid;

    enum
    {
        DAEMON_UNINIT = 0,
        DAEMON_RUNNING,
    } status;

    int restart_on_exit;

    int num_sockets;
    struct daemon_socket *sockets;
};

struct daemon_socket
{
    int socket;
    const char *env;
};

int
start_daemon(struct daemon *daemon);

#endif
