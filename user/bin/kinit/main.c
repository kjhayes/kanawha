
#include "config.h"
#include "daemon.h"
#include "path.h"
#include "log.h"
#include <stdio.h>
#include <unistd.h>

int main(int argc, const char **argv)
{
    int res;

    MSG_RAW("--- Kanawha OS ---\n");

    res = kinit_read_config();
    if(res) {
        return res;
    }

    {
        res = kinit_activate_root_path();
        if(res) {
            ERROR("Failed to create root filesystem!\n");
            return res;
        }
    }


    {
        struct kinit_daemon *d = kinit_daemons_begin();
        while(d) {
            INFO("Starting daemon \"%s\"\n",
                    kinit_daemon_get_name(d));
            sleep(1);
            res = kinit_daemon_start_manager(d);
            if(res) {
                ERROR("Failed to start manager for daemon \'%s\'\n",
                        kinit_daemon_get_name(d));
            }
            d = kinit_daemons_next(d);
        }
    }

    while(1) { // This is "init" we should *never* return
        // Sleep for 10 seconds at a time... (TODO: actually invoke `wait`)
        sleep(10);
    }

    // Exiting "init" is always an error
    return -1;
}

