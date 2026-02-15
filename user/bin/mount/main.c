
#include <kanawha/sys-wrappers.h>
#include <kanawha/mount.h>
#include <kanawha/file.h>
#include <getopt.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

const char *progname = "mount";

__attribute__((noreturn))
static void
panic_usage(void) {
    fprintf(stderr, "Usage: %s [MOUNT-POINT] [SOURCE] [-t FS-TYPE (default=ramfs)] [-s]\n",
            progname);
    exit(EXIT_FAILURE);
}

int main(int argc, const char **argv) {

    int res;

    if(argc > 0) {progname = argv[0];}

    int interactive = 0;
    int special_flag = 0;
    const char *fs_type = "ramfs";

    {
    int opt;
    while((opt = getopt(argc, (char**)argv, "t:s")) != -1) {
        switch(opt) {
            // Handle Any Short Options
            case 's':
                special_flag = 1;
                break;
            case 't':
                fs_type = optarg;
                break;
            default:
                panic_usage();
        }
    }
    }

    const char *mntpoint_path = NULL;
    const char *source = NULL;

    {
    int pos_argc = argc - optind;
    if(pos_argc < 0) {pos_argc = 0;}
    const char **pos_argv = argv + optind;

    if(pos_argc != 2) {
        panic_usage();
    }
    mntpoint_path = pos_argv[0];
    source = pos_argv[1];
    }

    unsigned long flags;
    if(special_flag) {
        flags = MOUNT_SPECIAL;
    } else {
        flags = MOUNT_FILE;
    }

    // Split the mount_pnt_path into a directory and a mntpoint name

    const char *dir_path = NULL;
    const char *mntpoint_name = NULL;

    // Remove leading spaces
    while(isspace(*mntpoint_path)) {
        mntpoint_path++;
    }

    char *split = strrchr(mntpoint_path, '/');
    if(split == NULL) {
        mntpoint_name = mntpoint_path;
        dir_path = ".";
    } else {
        mntpoint_name = split+1;
        dir_path = mntpoint_path;
        *split = '\0';
        if(strlen(dir_path) == 0) {
            dir_path = ".";
        }
    }

    fd_t dir;
    res = kanawha_sys_open(
            dir_path,
            FILE_PERM_READ,
            0,
            &dir);
    if(res) {
        fprintf(stderr, "mount: Failed to open directory \"%s\"\n", dir_path);
        return res;
    }

    res = kanawha_sys_mount(
            source,
            dir,
            mntpoint_name,
            fs_type,
            flags);
    if(res) {
        fprintf(stderr, "mount: mount syscall failed!\n");
        return res;
    }

    return 0;
}

