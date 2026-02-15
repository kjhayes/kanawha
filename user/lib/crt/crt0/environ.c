
#include <kanawha/sys-wrappers.h>
#include <kanawha/environ.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define ENVIRON_COUNT  256
#define ENVIRON_BUFLEN 0x4000

char **environ = NULL;

static char *environ_array[ENVIRON_COUNT];
static char environ_buffer[ENVIRON_BUFLEN];

int
__elk_crt__populate_environ(void)
{
    int res;

    memset(environ_array, 0, sizeof(environ_array));
    res = kanawha_sys_environ(
            NULL,
            environ_buffer,
            ENVIRON_BUFLEN,
            ENV_DUMP);
    if(res) {
        return res;
    }

    environ_buffer[ENVIRON_BUFLEN-1] = '\0';

    const char *bufend = environ_buffer + ENVIRON_BUFLEN;
    char *head = environ_buffer;
    size_t index = 0;
    while(head < bufend && index < ENVIRON_COUNT) {
        size_t len = strlen(head);
        if(len > 0) {
            environ_array[index] = head;
            index++;
        }
        head += (len + 1);
    }

    if(environ == NULL) {
        environ = environ_array;
    }

    return 0;
}

