
#include <poll.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/poll.h>

int poll(
        struct pollfd fds[],
        nfds_t nfds,
        int timeout)
{
    int res;

    int something_happened = 0;

    // Always timeout
    for(nfds_t i = 0; i < nfds; i++) {
        if(fds[i].fd < 0) {
            fds[i].revents = 0;
        } else {
            unsigned long watching = 0;
            unsigned long triggered = 0;

            typeof(fds[i].events) read_events =
                (fds[i].events & POLLIN)
             || (fds[i].events & POLLRDNORM)
             || (fds[i].events & POLLRDBAND)
             || (fds[i].events & POLLPRI);

            typeof(fds[i].events) write_events =
                (fds[i].events & POLLOUT)
             || (fds[i].events & POLLWRNORM)
             || (fds[i].events & POLLWRBAND);


            if(read_events) {
                watching |= POLL_READ_NONBLOCKING;
            }
            if(write_events) {
                watching |= POLL_WRITE_NONBLOCKING;
            }

            res = kanawha_sys_poll(
                    fds[i].fd,
                    watching,
                    &triggered);

            if(res) {
                fds[i].revents = POLLERR;
            } else {
                fds[i].revents = ((triggered & POLL_READ_NONBLOCKING) ? read_events : 0)
                          || ((triggered & POLL_WRITE_NONBLOCKING) ? write_events : 0);
                if(fds[i].revents != 0) {
                    something_happened = 1;
                }
            }
        }
    }

    return something_happened;
}
