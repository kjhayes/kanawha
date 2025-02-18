
#include <getopt.h>
#include <stddef.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

char *optarg;
int optind = 1;
static int optpos = 0;
int opterr = 1;
int optopt;

static void
move_arg_to_end(
        int argc,
        const char **argv,
        int index)
{
    const char *value = argv[index];
    for(int i = index+1; i < argc; i++) {
        argv[i-1] = argv[i];
    }
    argv[argc-1] = value;
}

static int
handle_long_arg(
        int argc,
        const char **argv,
        const char *optstring,
        struct option *longopts,
        int *longind)
{
    return '?';
}

static int
handle_short_arg(
        int argc,
        const char **argv,
        const char *optstring)
{
    int silent = 0;
    if(optstring[0] == ':') {
        optstring++;
        silent = 1;
    }

    const char *arg = argv[optind];

    if(optpos == 0) {
        optpos = 1;
    }

    char c = arg[optpos];
    optopt = c;

    if(!isgraph(c) ||
       c == '-' ||
       c == ':' ||
       c == ';')
    {
        if(!silent && opterr) {
            fprintf(stderr, "Invalid Command Line Option: \"%c\"\n", c);
        }
        return '?';
    }

    char *optstring_loc = strchr(optstring, (int)c);
    if(optstring_loc == NULL)
    {
        if(!silent && opterr) {
            fprintf(stderr, "Unrecognized Command Line Option: \"%c\"\n", c);
        }
        return '?';
    }

    int has_arg = 0;
    int arg_is_optional = 0;
    if(optstring_loc[1] == ':') {
        has_arg = 1;
        if(optstring_loc[2] == ':') {
            arg_is_optional = 1;
        }
    }

    // Handle arguments and advancing optind and optpos
    if(has_arg) {
        if(arg[optpos+1] == '\0') {
            // No more text in this argument
            if(!arg_is_optional) {
                if(optind + 1 >= argc) {
                    // Missing required argument
                    if(silent) {
                        return ':';
                    }
                    if(opterr) {
                        fprintf(stderr, "Missing required argument to option \"%c\"\n", c);
                    }
                    return '?';
                }
                // The argument is the next arg in argv
                optarg = (char *)argv[optind+1];
                optind += 2;
                optpos = 0;
            } else {
                // The argument is optional and not-present
                optarg = NULL;
                optind++;
                optpos = 0;
            }
        } else {
            // The argument is the rest of the text in this option
            optarg = (char*)(arg + optind + 1);
            optind++;
            optpos = 0;
        }
    } else {
        optpos++;
        if(arg[optpos] == '\0') {
            optind++;
            optpos = 0;
        }
    }

    return c;
}

static int
do_getopt(
        int argc,
        const char **argv,
        const char *optstring,
        struct option *longopts,
        int *longind)
{
    if(optind >= argc) {
        return -1;
    }

    while(1) {
      const char *arg = argv[optind];
      if(arg[0] == '-') {
          if(arg[1] == '-') {
              // Long Arg
              return handle_long_arg(
                      argc,
                      argv,
                      optstring,
                      longopts,
                      longind);
          }
          // Short Arg
          return handle_short_arg(
                  argc,
                  argv,
                  optstring);
      } else {
          // Non-Arg Option

          // Do a scan and see if there are any more options
          int more_options = 0;
          for(int i = optind+1; i < argc; i++) {
              if(argv[i][0] == '-') {
                  more_options = 1;
                  break;
              }
          }

          if(!more_options) {
              // All that is left is non-option args,
              // and optind points the first one
              return -1;
          } else {
              // Move this argument to the end of the list and try again
              // (There are faster ways to do this, but this is simple)
              move_arg_to_end(argc, argv, optind);
          }
      }
    }
}

int
getopt(
        int argc,
        const char **argv,
        const char *optstring)
{
    return getopt_long(
            argc,
            argv,
            optstring,
            NULL,
            NULL);
}

int
getopt_long(
        int argc,
        const char **argv,
        const char *optstring,
        struct option *longopts,
        int *longind)
{
    return do_getopt(
            argc,
            argv,
            optstring,
            longopts,
            longind);
}

