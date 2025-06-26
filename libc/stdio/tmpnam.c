
#include <stdio.h>
#include <unistd.h>
#include <kanawha/sys-wrappers.h>

static unsigned int __tmpname_call_no = 0;
static char __tmpnam_buffer[L_tmpname];

char *tmpnam(char *s)
{
    int res;

    char *buffer = s;
    if(s == NULL) {
        buffer = __tmpnam_buffer;
    }

    int pid = getpid();

    unsigned int counter = 0;
    
    int found_unique = 0;
    while(!found_unique) {
        snprintf(buffer, L_tmpname, "tmp-%u-%u", pid, counter);

        buffer[L_tmpname-1] = 0;

        res = access(buffer, F_OK);
        if(res == 0) {
            found_unique = 1;
            break;
        }
        if(counter == UINT_MAX) {
            found_unique = 0;
            break;
        }
        counter++;
    }

    if(!found_unique) {
        __tmpname_call_no++;
        return NULL;
    }

    __tmpname_call_no++;
    return buffer;
}
