
#include <stdio.h>
#include <stdlib.h>
#include "frame.h"
#include "display.h"
#include "frame.h"
#include "buffer.h"
#include "input.h"
#include "state.h"
#include "command.h"

int main(int argc, const char **argv)
{
    int res;

    if(argc != 2) {
        exit(EXIT_FAILURE);
    }
    const char *path = argv[1];

    frame_init();
    display_init();
    input_init();
    add_file_input_source(stdin);
    buffer_init();
    add_buffer_with_path(path);
    command_init();

    while(kvi.running)
    {
        char c = input_getc();
        switch(c) {
            case ':': {
                handle_command();
            }
            default: {
                struct frame *frame = frame_get_root();
                frame_lock(frame);
                frame_set_char(frame,5,5,c);
                frame_unlock(frame);
                display_flush();
            }
        }
    }

    command_deinit();
    buffer_deinit();
    input_deinit();
    display_deinit();
    frame_deinit();

    return 0;
}

