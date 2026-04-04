
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <kanawha/file.h>
#include <kanawha/spawn.h>
#include <kanawha/sys-wrappers.h>
#include <kfb/kfb.h>
#include <windd/windd.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <threads.h>

#include "ansi.h"
#include "color.h"
#include "font.h"
#include "render.h"
#include "input.h"
#include "term.h"

static const char *prog_name = "fbterm";

//static inline void
//find_maximum_fb_mode(struct kfb_framebuffer *fb,
//                     int *best_mode_out,
//                     int *best_layer_out)
//{
//    int best_mode = -EINVAL;
//    int best_layer = -EINVAL;
//    size_t best_dimensions = 0;
//    int mode = 0;
//
//    while(1)
//    {
//        struct fb_mode_info *info = kfb_load_mode_info(fb, mode);
//        if(info == NULL)
//        {
//            break;
//        }
//
//        for(int layer = 0; layer < info->layer_count; layer++)
//        {
//            struct fb_layer_info *layer_info = &info->layer_infos[layer];
//            size_t dimensions;
//            switch(layer_info->layout.format)
//            {
//            case GFX_FORMAT_ASCII:
//            case GFX_FORMAT_VGA_CHAR:
//                dimensions = 0;
//                break;
//            default:
//                dimensions =
//                    layer_info->layout.width * layer_info->layout.height;
//                break;
//            }
//
//            if(dimensions > best_dimensions)
//            {
//                best_mode = mode;
//                best_layer = layer;
//                break;
//            }
//        }
//
//        kfb_unload_mode_info(fb, info);
//        mode++;
//    }
//
//    *best_mode_out = best_mode;
//    *best_layer_out = best_layer;
//}

static inline void
panic_usage(void)
{
    fprintf(stderr,
            "Usage: %s [-f framebuffer] [-t psf1-font] [-m mode] [-l layer] [SHELL] [SHELL-ARGS...]"
            "[-d log_file]\n",
            prog_name);
    exit(EXIT_FAILURE);
}

struct shell {
    int shell_pid;
    int shell_stdin;
    int shell_stdout;
    int shell_stdout_hijack;
};

static struct shell shell = {};

int
shell_input_main(void *_input_ctx)
{
    struct input_ctx *ctx = _input_ctx;
    int running = 1;
    while(running) {
        char c = input_getc(ctx);
        write(shell.shell_stdout_hijack, &c, 1);
        write(shell.shell_stdin, &c, 1);
    }
}

static int
launch_shell(int argc, const char **argv)
{
    int shell_stdin[2];
    int shell_stdout[2];
    pipe(shell_stdin);
    pipe(shell_stdout);

    int pid = fork();
    if(pid == 0) {
        // We are becoming the shell
        dup2(shell_stdin[0], 0);
        dup2(shell_stdout[1], 1);
        dup2(shell_stdout[1], 2);
        execvp(argv[0], (char**)argv);
        exit(EXIT_FAILURE);
    }

    shell.shell_pid = pid;
    shell.shell_stdin = shell_stdin[1];
    shell.shell_stdout = shell_stdout[0];
    shell.shell_stdout_hijack = shell_stdout[1];
    close(shell_stdin[0]);
    return 0;
}

int
main(int argc, const char **argv)
{
    int res;

    if(argc > 0)
    {
        prog_name = argv[0];
    }

    FILE *log_file = NULL;
    const char *log_file_path = NULL;

    const char *font_path = NULL;
    const char *fb_path = NULL;
    int mode = 0;
    int layer = 0;

    int opt;
    while((opt = getopt(argc, (char **)argv, "f:t:m:l:d:")) != -1)
    {
        switch(opt)
        {
        case 'f':
            fb_path = optarg;
            break;
        case 'd':
            log_file_path = optarg;
            break;
        case 't':
            font_path = optarg;
            break;
        case 'm':
            mode = atoi(optarg);
            break;
        case 'l':
            layer = atoi(optarg);
            break;
        default:
            panic_usage();
        }
    }

    int shell_argc;
    const char **shell_argv;
    {
        int pos_argc = argc - optind;
        if(pos_argc < 0) {
            pos_argc = 0;
        }
        const char **pos_argv = argv + optind;

        if(pos_argc <= 0) {
            panic_usage();
        }

        shell_argc = pos_argc;
        shell_argv = pos_argv;
    }

    printf("SHELL:");
    for(size_t i = 0; i < shell_argc; i++) {
        printf(" %s", shell_argv[i]);
    }
    printf("\n");

    launch_shell(shell_argc, shell_argv);

    if(font_path == NULL)
    {
        panic_usage();
    }

    if(log_file_path != NULL)
    {
        log_file = fopen(log_file_path, "w");
    }

    struct font_data *fdata = load_font(font_path);
    if(fdata == NULL)
    {
        fprintf(stderr, "Failed to load font \"%s\"!\n", font_path);
        exit(EXIT_FAILURE);
    }
    
    struct window *window = NULL;
    struct render_ctx *render = NULL;
    struct input_ctx *input_for_shell = NULL;

    if(fb_path != NULL) {
        struct kfb_framebuffer *fb = kfb_open_framebuffer(fb_path);
        if(fb == NULL)
        {
            fprintf(stderr, "Failed to open framebuffer: \"%s\"!\n", fb_path);
            exit(EXIT_FAILURE);
        }

        res = kfb_set_current_mode(fb, mode);
        if(res)
        {
            fprintf(stderr, "Failed to set framebuffer mode to %d!\n", mode);
            exit(EXIT_FAILURE);
        }
        render = create_fb_render_ctx(fb, layer);
        input_for_shell = create_file_input_ctx(stdin);
    } else {
        windd_client_init();
        window = windd_client_open();
        if(window == NULL) {
            fprintf(stderr, "failed to create window!\n");
            exit(EXIT_FAILURE);
        }
        render = create_windd_render_ctx(window);
        input_for_shell = create_windd_input_ctx(window);
    }
    
    if(input_for_shell == NULL) {
        fprintf(stderr, "failed to create input context!\n");
        exit(EXIT_FAILURE);
    }

    if(render == NULL) {
        fprintf(stderr, "failed to create render context!\n");
        exit(EXIT_FAILURE);
    }

    thrd_t shell_input_thrd;
    res = thrd_create(
            &shell_input_thrd,
            shell_input_main,
            input_for_shell);
    if(res) {
        fprintf(stderr, "failed to create shell input thread!\n");
        exit(EXIT_FAILURE);
    }

    struct input_ctx *input_from_shell;
    FILE *shell_stdout_file = fdopen(shell.shell_stdout, "r");
    input_from_shell = create_file_input_ctx(shell_stdout_file);

#define TERM_WIDTH 80
#define TERM_HEIGHT 50

    res = init_terminal(log_file, TERM_WIDTH, TERM_HEIGHT);
    if(res)
    {
        fprintf(stderr, "Failed to allocate terminal buffer!\n");
        exit(EXIT_FAILURE);
    }

    res = ansi_terminal_init(&terminal_data);
    if(res)
    {
        fprintf(stderr, "Failed to init ansi terminal!\n");
        exit(EXIT_FAILURE);
    }

    while(terminal_data.running)
    {
        render_update(&terminal_data, fdata, render);

        ansi_terminal_update(&terminal_data, input_from_shell);
        for(size_t __i = 0; __i < 256; __i++)
        {
            if(input_poll(input_from_shell)) {
                ansi_terminal_update(&terminal_data, input_from_shell);
            } else {
                break;
            }
        }
    }

    deinit_terminal();
    unload_font(fdata);
    destroy_input_ctx(input_for_shell);
    destroy_input_ctx(input_from_shell);
    destroy_render_ctx(render);
    if(window) {
        windd_client_close(window);
        window = NULL;
        windd_client_deinit();
    }
    return 0;
}
