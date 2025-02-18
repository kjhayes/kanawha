
#include "elk-libc-internal/null.h"

#include <stdio.h>
#include <stdlib.h>

int system(const char *string)
{
    if(string == NULL) {
        return 0; // Indicate that there is no support for a command processor
    } else {
        fprintf(stderr, "Tried to invoke \"system\" with command: \"%s\"",
                string);
        abort();
    }
}

