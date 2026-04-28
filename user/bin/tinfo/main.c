
#include <stdio.h>
#include <ansiterm/ansiterm.h>
#include <termios.h>

static struct termios old_stdin;
static struct termios old_stdout;

int
init_term(void)
{
    int res;
    tcgetattr(fileno(stdin), &old_stdin);
    tcgetattr(fileno(stdout), &old_stdout);
    struct termios new_stdin = old_stdin;
    struct termios new_stdout = old_stdout;
    new_stdin.c_lflag &= ~(ICANON);
    new_stdin.c_lflag &= ~(ECHO);
    new_stdin.c_lflag &= ~(ECHOE);
    new_stdin.c_lflag &= ~(ECHOK);
    new_stdin.c_lflag &= ~(ECHONL);
    new_stdout.c_lflag &= ~(ICANON);
    new_stdout.c_lflag &= ~(ECHO);
    new_stdout.c_lflag &= ~(ECHOE);
    new_stdout.c_lflag &= ~(ECHOK);
    new_stdout.c_lflag &= ~(ECHONL);
    res = tcsetattr(fileno(stdin), TCSANOW, &new_stdin);
    if(res) {
        printf("failed to set stdin terminal attributes!\n");
        return res;
    }
    res = tcsetattr(fileno(stdout), TCSANOW, &new_stdout);
    if(res) {
        printf("failed to set stdout terminal attributes!\n");
        return res;
    }
    return 0;
}

int
deinit_term(void)
{
    tcsetattr(fileno(stdin), TCSANOW, &old_stdin);
    tcsetattr(fileno(stdout), TCSANOW, &old_stdout);
    return 0;
}

int main(int argc, const char **argv)
{
    unsigned long width, height;

    init_term();
    ansiterm_get_dimensions(&width, &height);
    deinit_term();

    printf("Terminal Dimensions (%lu,%lu)\n",
            width, height);

    return 0;
}

