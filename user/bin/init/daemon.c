
#include "daemon.h"
#include <errno.h>
#include <kanawha/sys-wrappers.h>
#include <stdlib.h>
#include <unistd.h>
#include <sock/sock.h>

#include "log.h"

int
start_daemon(struct daemon *daemon)
{
    int res;

    if(daemon->status == DAEMON_UNINIT)
    {
        // Setup the sockets
        for(int i = 0; i < daemon->num_sockets; i++)
        {
            struct daemon_socket *sock = &daemon->sockets[i];
            res = sock_create_socket(sock->env);
            if(res) {
                return res;
            }
        }
    }

    int fork_pid = fork();
    if(fork_pid == 0)
    {
        // We are the child
        INFO("running daemon: %s\n", daemon->command);
        execvp(daemon->command, (char **)daemon->args);
        ERROR("Failed to run daemon \"%s\"!\n", daemon->command);
        perror("execvp");
        exit(-1);
    }
    INFO("forked daemon: %s\n", daemon->command);
    daemon->pid = fork_pid;
    daemon->status = DAEMON_RUNNING;

    sleep(1);

    return 0;
}
