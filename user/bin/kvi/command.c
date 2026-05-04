
#include "input.h"
#include "state.h"
#include <stdint.h>
#include <stdio.h>

#define COMMAND_BUFLEN (128)

int command_init(void)
{
    return 0;
}
int command_deinit(void)
{
    return 0;
}

int
handle_command(void)
{
    char linebuf[COMMAND_BUFLEN] = {0};
    size_t linelen = 0;

    int eol = 0;
    while(!eol) {
        char c = input_getc();
        switch(c) {
            case '\r':
                // Ignore these characters
                continue;

            case '\n':
                // Submit the command
                eol = 1;
                continue;

            case '\b':
                // Backspace
                if(linelen > 0) {
                    linelen--;
                    linebuf[linelen] = '\0';
                }
                continue;
        }

        if(linelen >= COMMAND_BUFLEN-1) {
            continue;
        }

        linebuf[linelen] = c;
        linelen++;
    }

    linebuf[COMMAND_BUFLEN-1] = '\0';

    for(size_t i = 0; i < COMMAND_BUFLEN; i++) {
        char c = linebuf[i];
        if(c == '\0') {
            break;
        }
        switch(c) {
            case 'q':
                kvi.running = 0;
                break;
            default:
                break;
        }
    }

    return 0;
}
