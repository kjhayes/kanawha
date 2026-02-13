
int isblank(int i)
{
    char c = i;
    switch(c) {
        case '\t':
        case ' ':
            return 1;
        default:
            return 0;
    }
}

