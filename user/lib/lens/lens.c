
#include <lens/lens.h>
#include <lens/internal.h>
#include <sock/sock.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

struct sock_socket *__lens_socket = NULL;

int lens_init(void)
{
    if(__lens_socket != NULL) {
        return -EINVAL;
    }
    __lens_socket = sock_open_socket("LENSD_SOCKET");
    if(__lens_socket == NULL) {
        return -ENXIO;
    }
    return 0;
}
int lens_deinit(void)
{
    int res;
    if(__lens_socket == NULL) {
        return -EINVAL;
    }
    res = sock_close_socket(__lens_socket);
    if(res) {
        return res;
    }
    __lens_socket = NULL;
    return 0;
}

