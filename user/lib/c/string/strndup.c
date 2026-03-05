
#include <stdlib.h>
#include <string.h>

char *
strndup(const char *string, size_t n)
{
    size_t len = strlen(string);
    if(len > n)
    {
        len = n;
    }
    char *buffer = malloc(len + 1);
    strncpy(buffer, string, len + 1);
    buffer[len] = '\0';
    return buffer;
}
