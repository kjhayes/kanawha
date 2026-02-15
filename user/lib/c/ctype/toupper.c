
#include <ctype.h>

int toupper(int i)
{
    if(!islower(i)) {
        return i;
    }

    return (i + 'A') - 'a';
}
