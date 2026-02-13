#ifndef __ELK_LIBC__GETOPT_H__
#define __ELK_LIBC__GETOPT_H__

extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;

struct option {
    const char *name;
    int has_arg;
    int *flag;
    int val;
};

#define no_argument 0
#define required_argument 1
#define optional_argument 2

extern int
getopt(
        int argc,
        char **argv,
        const char *optstring);

extern int
getopt_long(
        int argc,
        char **argv,
        const char *optstring,
        struct option *longopts,
        int *longind);



#endif
