
#include "daemon.h"
#include <kanawha/sys-wrappers.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"

int start_daemon(struct daemon *daemon)
{ 
    int res;

    if(daemon->status == DAEMON_UNINIT) {
        // Setup the sockets
        for(int i = 0; i < daemon->num_sockets; i++) {
            struct daemon_socket *sock = &daemon->sockets[i];
            int file;
            res = kanawha_sys_socket(
                    0,
                    0,
                    &file);
            if(res) {
                return res;
            }
            sock->socket = file;
            char SOCK_NUM_BUFFER[64];
            snprintf(SOCK_NUM_BUFFER, 64, "%d", file);
            SOCK_NUM_BUFFER[64-1] = '\0';
            setenv(sock->env, SOCK_NUM_BUFFER, 1);
        }
    }
    
    int fork_pid = fork();
    if(fork_pid == 0) {
        // We are the child
        INFO("running daemon: %s\n", daemon->command); 
        execvp(daemon->command, (char**)daemon->args);
        ERROR("Failed to run daemon \"%s\"!\n", daemon->command);
        perror("execvp");
        exit(-1);
    }
    INFO("forked daemon: %s\n", daemon->command); 
    daemon->pid = fork_pid;
    daemon->status = DAEMON_RUNNING;
    return 0;
}

