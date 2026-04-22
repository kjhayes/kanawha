
#include <stdio.h>

#undef fgets_unlocked
char *
fgets_unlocked(char *restrict s, int n, FILE *restrict stream)
{
    char *stashed_s = s;
    int num_read = 0;
    while(n > 1)
    {
        char c = fgetc_unlocked(stream);
        *s = c;
        if(c == EOF)
        {
            break;
        }
        num_read++;
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
    if(num_read == 0)
    {
        return NULL;
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
