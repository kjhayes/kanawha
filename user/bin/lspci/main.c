
#include <errno.h>
#include <getopt.h>
#include <kanawha/file.h>
#include <kanawha/sys-wrappers.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pciids.h"

const char *progname = "lspci";

__attribute__((noreturn)) static void
panic_usage(void)
{
    fprintf(stderr, "Usage: %s [-s SYSFS_PCI_DIR] [-p PCI_IDS_PATH] [-i]\n",
            progname);
    exit(EXIT_FAILURE);
}

extern int
dump_pci_file(fd_t file);

int
main(int argc, const char **argv)
{
    int res;

    if(argc > 0)
    {
        progname = argv[0];
    }

    const char *sysfs_pci_dir_path = "/sys/pci/";
    const char *pciids_path = "/sys/initrd/pci.ids";

    int interactive = 0;

    {
        int opt;
        while((opt = getopt(argc, (char **)argv, "s:p:i")) != -1)
        {
            switch(opt)
            {
            // Handle Any Short Options
            case 's':
                sysfs_pci_dir_path = optarg;
                break;
            case 'p':
                pciids_path = optarg;
                break;
            case 'i':
                interactive = 1;
                break;
            default:
                panic_usage();
            }
        }
    }

    {
        int pos_argc = argc - optind;
        if(pos_argc < 0)
        {
            pos_argc = 0;
        }
        const char **pos_argv = argv + optind;

        for(int i = 0; i < pos_argc; i++)
        {
            // Handle any positional arguments
            panic_usage();
        }
    }

    res = init_pciids(pciids_path);
    if(res) {
        fprintf(stderr, "Warning: failed to read PCI ID database file!\n");
    }

    fd_t sysfs_pci_dir;

    res =
        kanawha_sys_open(sysfs_pci_dir_path, FILE_PERM_READ, 0, &sysfs_pci_dir);
    if(res)
    {
        fprintf(stderr,
                "Failed to open directory \"%s\"!\n",
                sysfs_pci_dir_path);
        return res;
    }

    res = kanawha_sys_dirbegin(sysfs_pci_dir);
    if(res && res != -ENXIO)
    {
        fprintf(stderr,
                "Failed to scan directory \"%s\"!\n",
                sysfs_pci_dir_path);
        return res;
    }
    if(res == -ENXIO)
    {
        return 0;
    }

#define MAX_NAMELEN 128
    size_t dir_pathlen = strlen(sysfs_pci_dir_path);
    char pathbuf[dir_pathlen + 1 + MAX_NAMELEN + 1];

    strncpy(pathbuf, sysfs_pci_dir_path, dir_pathlen + 1);
    pathbuf[dir_pathlen] = '/';

    char *namebuf = pathbuf + dir_pathlen + 1;

    while(res == 0)
    {
        res = kanawha_sys_dirname(sysfs_pci_dir, namebuf, MAX_NAMELEN);
        if(res)
        {
            kanawha_sys_close(sysfs_pci_dir);
            fprintf(stderr,
                    "Failed to get name of file inside \"%s\"!\n",
                    sysfs_pci_dir_path);
            return res;
        }

        namebuf[MAX_NAMELEN] = '\0';

        if(namebuf[0] != '.')
        {
            fd_t file;
            res = kanawha_sys_open(pathbuf, FILE_PERM_READ, 0, &file);
            if(res)
            {
                kanawha_sys_close(sysfs_pci_dir);
                fprintf(stderr, "Failed to open file \"%s\"!\n", pathbuf);
                return res;
            }

            dump_pci_file(file);
            kanawha_sys_close(file);

            if(interactive)
            {
                char c = getchar();
                if(c == 'q')
                {
                    kanawha_sys_close(sysfs_pci_dir);
                    exit(EXIT_SUCCESS);
                }
            }
        }

        res = kanawha_sys_dirnext(sysfs_pci_dir);
        if(res)
        {
            kanawha_sys_close(sysfs_pci_dir);
            if(res == -ENXIO)
            {
                break;
            }
            else
            {
                fprintf(stderr,
                        "Failed to scan directory \"%s\"!\n",
                        sysfs_pci_dir_path);
                return res;
            }
        }
    }

    return 0;
}
