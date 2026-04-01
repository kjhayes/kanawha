
#include <errno.h>
#include <kanawha/sys-wrappers.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int
main(int argc, const char **argv)
{
    int res;

    while(1) {}

    return 0;

//    int socket;
//    {
//        const char *socket_env = getenv("RANDD_SOCKET");
//        if(socket_env == NULL)
//        {
//            fprintf(stderr,
//                    "randd: failed to get RANDD_SOCKET environment "
//                    "variable!\n");
//            return -EINVAL;
//        }
//        socket = strtoul(socket_env, NULL, 10);
//    }
//
//    res = kanawha_sys_faccess(socket, FACCESS_NON_BLOCKING, FACCESS_MODE_CLEAR);
//    if(res)
//    {
//        fprintf(stderr, "randd: Failed to make socket blocking!\n");
//        return res;
//    }
//
//    int running = 1;
//    while(running)
//    {
//
//        do
//        {
//            res = waitpid(-1, NULL, WNOHANG);
//        } while(res > 0);
//
//        if(res < 0)
//        {
//            fprintf(stderr, "randd: Failed to wait for children!\n");
//        }
//
//        int conn;
//        // res = kanawha_sys_accept(socket, &conn, 0);
//        if(res)
//        {
//            continue;
//        }
//
//        int child = fork();
//
//        if(child == 0)
//        {
//
//            res = kanawha_sys_faccess(socket,
//                                      FACCESS_NON_BLOCKING,
//                                      FACCESS_MODE_CLEAR);
//            if(res)
//            {
//                fprintf(stderr,
//                        "randd: Failed to make socket "
//                        "non-blocking!\n");
//                close(conn);
//                continue;
//            }
//
//            while(1)
//            {
//                res = write(conn, "poyo", 4);
//                if(res <= 0)
//                {
//                    close(conn);
//                    return res;
//                }
//            }
//        }
//        else
//        {
//            close(conn);
//        }
//    }
//
//    close(socket);
//    return 0;
}
