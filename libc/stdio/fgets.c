
#include <stdio.h>

char *
fgets(
        char * restrict s,
        int n,
        FILE * restrict stream)
{
    char *stashed_s = s;
    while(n>1) {
        char c = fgetc(stream);
        *s = c;
        if(c != EOF) {
            s++;
            n--;
        } else {
            break;
        }
        if(c == '\n') {
            break;
        }
    }
    if(n >= 1) {
        *s = '\0';
    }
    return stashed_s;
}

