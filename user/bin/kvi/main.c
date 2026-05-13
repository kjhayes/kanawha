
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


    const char *path;
    if(argc > 1) {
        path = argv[1];
    } else {
        path = NULL;
    }

    frame_init();
    display_init();
    input_init();
    add_file_input_source(stdin);
    buffer_init();
    if(path != NULL) {
        add_buffer_with_path(path);
    } else {
        add_buffer();
    }
    command_init();

    struct frame *frame = frame_get_root();
    frame_lock(frame);
    frame_set_char(frame,0,0,'!');
    frame_unlock(frame);
    display_flush();

    while(kvi.running)
    {
        char c = input_getc();
        switch(c) {
            case ':': {
                handle_command();
            } break;
            default: {
            } break;
        }
    }

    command_deinit();
    buffer_deinit();
    input_deinit();
    display_deinit();
    frame_deinit();

    return 0;
}

