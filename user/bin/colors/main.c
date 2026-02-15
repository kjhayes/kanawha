
#include <stdio.h>

int main(int argc, const char **argv)
{

#define COLOR_XLIST(X)\
X(ANSI_BLACK,           "\033[30m")\
X(ANSI_RED,             "\033[31m")\
X(ANSI_GREEN,           "\033[32m")\
X(ANSI_YELLOW,          "\033[33m")\
X(ANSI_BLUE,            "\033[34m")\
X(ANSI_MAGENTA,         "\033[35m")\
X(ANSI_CYAN,            "\033[36m")\
X(ANSI_WHITE,           "\033[37m")\
X(ANSI_BRIGHT_BLACK,    "\033[90m")\
X(ANSI_BRIGHT_RED,      "\033[91m")\
X(ANSI_BRIGHT_GREEN,    "\033[92m")\
X(ANSI_BRIGHT_YELLOW,   "\033[93m")\
X(ANSI_BRIGHT_BLUE,     "\033[94m")\
X(ANSI_BRIGHT_MAGENTA,  "\033[95m")\
X(ANSI_BRIGHT_CYAN,     "\033[96m")\
X(ANSI_BRIGHT_WHITE,    "\033[97m")\
X(ANSI_RESET,           "\033[0m")

#define DEF_CONST_STRS(NAME, STR)\
    static const char *NAME = STR;
    COLOR_XLIST(DEF_CONST_STRS)
#undef DEF_CONST_STRS

    #define RESET "\033[0m"

#define PRINT_COLOR(NAME,STR)\
    printf(STR #NAME " " RESET);
    COLOR_XLIST(PRINT_COLOR)
#undef PRINT_COLOR

    return 0;
}

