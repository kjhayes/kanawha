
#include <stdio.h>

#undef fgets_unlocked
char *
fgets_unlocked(char *restrict s, int n, FILE *restrict stream)
{
    char *stashed_s = s;
    while(n > 1)
    {
        char c = fgetc(stream);
        *s = c;
        if(c == EOF)
        {
            break;
        }
        s++;
        n--;
        if(c == '\n')
        {
            break;
        }
    }
    if(n >= 1)
    {
        *s = '\0';
    }
    return stashed_s;
}

#undef fgets
char *
fgets(char *restrict s, int n, FILE *restrict stream)
{
    char *ret;
    flockfile(stream);
    ret = fgets_unlocked(s, n, stream);
    funlockfile(stream);
    return ret;
}
