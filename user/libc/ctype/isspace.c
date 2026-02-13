
int isspace(int i)
{
    char c = i;
    return ((c >= 0x0A) && (c <= 0x0D)) ||
           (c == ' ');
}

