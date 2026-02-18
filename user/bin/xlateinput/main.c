
#include <stdio.h>

#include <kanawha/input.h>

const char *progname = "xlateinput";

void
handle_input_event(
        struct input_event *evt)
{
    static int shift_pressed = 0;
    static int ctrl_pressed = 0;

    input_key_t key = evt->key;
    input_motion_t motion = evt->motion;

    if(motion == INPUT_MOTION_RELEASED) {
        switch(key) {
            case INPUT_KEY_LSHIFT:
                shift_pressed = 0;
                break;
            case INPUT_KEY_LCTRL:
                ctrl_pressed = 0;
                break;
            default:
                break;
        }
    } else {

        int no_char = 0;
        int ctrl_char = 0;
        char c;
        switch(key) {
            case INPUT_KEY_LCTRL:
                ctrl_pressed = 1;
                ctrl_char = 1;
                return;
            case INPUT_KEY_LSHIFT:
                shift_pressed = 1;
                ctrl_char = 1;
                return;
            default:
                break;
        }

        if(ctrl_pressed) {
            switch(key) {
            case INPUT_KEY_A: c = 0x01; break; // ^A Start of Heading
            case INPUT_KEY_B: c = 0x02; break; // ^B Start of Text
            case INPUT_KEY_C: c = 0x03; break; // ^C End of Text
            case INPUT_KEY_D: c = 0x04; break; // ^D End of Transmission
            case INPUT_KEY_E: c = 0x05; break;
            case INPUT_KEY_F: c = 0x06; break;
            case INPUT_KEY_G: c = 0x07; break; // Bel
            case INPUT_KEY_H: c = 0x08; break; // Backspace
            case INPUT_KEY_I: c = 0x09; break; // Tab
            case INPUT_KEY_J: c = 0x0A; break; // LF
            case INPUT_KEY_K: c = 0x0B; break; // VT
            case INPUT_KEY_L: c = 0x0C; break; // FF
            case INPUT_KEY_M: c = 0x0D; break; // CR
            case INPUT_KEY_N: c = 0x0E; break; // Shift Out
            case INPUT_KEY_O: c = 0x0F; break; // Shift In
            case INPUT_KEY_P: c = 0x10; break;
            case INPUT_KEY_Q: c = 0x11; break;
            case INPUT_KEY_R: c = 0x12; break;
            case INPUT_KEY_S: c = 0x13; break;
            case INPUT_KEY_T: c = 0x14; break;
            case INPUT_KEY_U: c = 0x15; break;
            case INPUT_KEY_V: c = 0x16; break;
            case INPUT_KEY_W: c = 0x17; break;
            case INPUT_KEY_X: c = 0x18; break;
            case INPUT_KEY_Y: c = 0x19; break;
            case INPUT_KEY_Z: c = 0x1A; break;
            case INPUT_KEY_OPEN_SQR: c = 0x1B; break; // ESC
            case INPUT_KEY_BSLASH: c = 0x1C; break; // File Sep.
            default: no_char = 1; break;
            }
        } else {
            switch(key) {
            case INPUT_KEY_A: c = shift_pressed ? 'A' : 'a'; break;
            case INPUT_KEY_B: c = shift_pressed ? 'B' : 'b'; break;
            case INPUT_KEY_C: c = shift_pressed ? 'C' : 'c'; break;
            case INPUT_KEY_D: c = shift_pressed ? 'D' : 'd'; break;
            case INPUT_KEY_E: c = shift_pressed ? 'E' : 'e'; break;
            case INPUT_KEY_F: c = shift_pressed ? 'F' : 'f'; break;
            case INPUT_KEY_G: c = shift_pressed ? 'G' : 'g'; break;
            case INPUT_KEY_H: c = shift_pressed ? 'H' : 'h'; break;
            case INPUT_KEY_I: c = shift_pressed ? 'I' : 'i'; break;
            case INPUT_KEY_J: c = shift_pressed ? 'J' : 'j'; break;
            case INPUT_KEY_K: c = shift_pressed ? 'K' : 'k'; break;
            case INPUT_KEY_L: c = shift_pressed ? 'L' : 'l'; break;
            case INPUT_KEY_M: c = shift_pressed ? 'M' : 'm'; break;
            case INPUT_KEY_N: c = shift_pressed ? 'N' : 'n'; break;
            case INPUT_KEY_O: c = shift_pressed ? 'O' : 'o'; break;
            case INPUT_KEY_P: c = shift_pressed ? 'P' : 'p'; break;
            case INPUT_KEY_Q: c = shift_pressed ? 'Q' : 'q'; break;
            case INPUT_KEY_R: c = shift_pressed ? 'R' : 'r'; break;
            case INPUT_KEY_S: c = shift_pressed ? 'S' : 's'; break;
            case INPUT_KEY_T: c = shift_pressed ? 'T' : 't'; break;
            case INPUT_KEY_U: c = shift_pressed ? 'U' : 'u'; break;
            case INPUT_KEY_V: c = shift_pressed ? 'V' : 'v'; break;
            case INPUT_KEY_W: c = shift_pressed ? 'W' : 'w'; break;
            case INPUT_KEY_X: c = shift_pressed ? 'X' : 'x'; break;
            case INPUT_KEY_Y: c = shift_pressed ? 'Y' : 'y'; break;
            case INPUT_KEY_Z: c = shift_pressed ? 'Z' : 'z'; break;
            case INPUT_KEY_1: c = shift_pressed ? '!' : '1'; break;
            case INPUT_KEY_2: c = shift_pressed ? '@' : '2'; break;
            case INPUT_KEY_3: c = shift_pressed ? '#' : '3'; break;
            case INPUT_KEY_4: c = shift_pressed ? '$' : '4'; break;
            case INPUT_KEY_5: c = shift_pressed ? '%' : '5'; break;
            case INPUT_KEY_6: c = shift_pressed ? '^' : '6'; break;
            case INPUT_KEY_7: c = shift_pressed ? '&' : '7'; break;
            case INPUT_KEY_8: c = shift_pressed ? '*' : '8'; break;
            case INPUT_KEY_9: c = shift_pressed ? '(' : '9'; break;
            case INPUT_KEY_0: c = shift_pressed ? ')' : '0'; break;
            case INPUT_KEY_MINUS: c = shift_pressed ? '_' : '-'; break;
            case INPUT_KEY_EQUAL_SIGN: c = shift_pressed ? '+' : '='; break;
            case INPUT_KEY_BACKTICK: c = shift_pressed ? '~' : '`'; break;
            case INPUT_KEY_COMMA: c = shift_pressed ? '<' : ','; break;
            case INPUT_KEY_PERIOD: c = shift_pressed ? '>' : '.'; break;
            case INPUT_KEY_FSLASH: c = shift_pressed ? '?' : '/'; break;
            case INPUT_KEY_SEMICOLON: c = shift_pressed ? ':' : ';'; break;
            case INPUT_KEY_SINGLE_QUOT: c = shift_pressed ? '"' : '\''; break;
            case INPUT_KEY_OPEN_SQR: c = shift_pressed ? '{' : '['; break;
            case INPUT_KEY_CLOSE_SQR: c = shift_pressed ? '}' : ']'; break;
            case INPUT_KEY_BSLASH: c = shift_pressed ? '|' : '\\'; break;
            case INPUT_KEY_SPACE: c = ' '; break;
            case INPUT_KEY_TAB: c = '\t'; break;
            case INPUT_KEY_ENTER: c = '\n'; break;
            case INPUT_KEY_BACKSPACE: c = '\b'; break;
            case INPUT_KEY_ESCAPE: c = 033; break;
            default: no_char = 1; break;
            }
        }

        if(!no_char && !ctrl_char) {
            putchar(c);
        } else if(no_char) {
            putchar('?');
        } else { // ctrl_char
            // Do nothing
        }
    }
}

int main(int argc, const char **argv)
{
    int res;

    if(argc > 0) {
        progname = argv[0];
    }

    if(argc != 2) {
        fprintf(stderr,
                "USAGE: %s [INPUT-PATH]\n",
                progname);
        return -1;
    }

    const char *input_path = argv[1];
    
    FILE *input = fopen(input_path, "r");

    struct input_event event;
    
    while(1) {
        size_t read = fread(&event, sizeof(struct input_event), 1, input);
        if(read == 0) {
            continue; // Should probably break and report error
        }
        if(read != 1) {
            fprintf(stderr, "Failed to read whole keyboard event!\n");
            continue;
        }

        handle_input_event(&event);
    }

    return 0;
}

