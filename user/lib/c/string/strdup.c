
#include <stdlib.h>
#include <string.h>

char *strdup(const char *string)
{
    size_t len = strlen(string);
    char *buffer = malloc(len+1);
    buffer[len] = '\0';
    strcpy(buffer, string);
    return buffer;
}

