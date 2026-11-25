
#include <lens/lens.h>
#include <sock/socket.h>
#include <errno.h>
#include <unistd.h>

struct sock_socket *lens_socket = NULL;

int lens_init(void)
{
    if(lens_socket != NULL) {
        return -EINVAL;
    }
    lens_socket = sock_open_env_socket("LENSD_SOCKET");
    if(lens_socket == NULL) {
        return -ENXIO;
    }
    return 0;
}
int lens_deinit(void)
{
    int res;
    if(lens_socket == NULL) {
        return -EINVAL;
    }
    res = sock_close_socket(lens_socket);
    if(res) {
        return res;
    }
    lens_socket = NULL;
    return 0;
}

