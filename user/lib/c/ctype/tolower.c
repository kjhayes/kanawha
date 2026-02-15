
#include <ctype.h>

int tolower(int i)
{
    if(!isupper(i)) {
        return i;
    }

    return (i + 'a') - 'A';
}

