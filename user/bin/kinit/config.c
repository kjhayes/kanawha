
#include "config.h"
#include "daemon.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <lassie/json.h>

const char *root_paths[] = {
    "/kinit.config",
    "/kinit.cfg",
    "/kinit/config",
    "/etc/kinit.config",
    "/etc/kinit.cfg",
    "/etc/kinit/config",
    0,
};

static FILE *
kinit_open_root_config(void)
{
    unsigned long i = 0;
    while(root_paths[i] != 0) {
        const char *path = root_paths[i];
        FILE *f = fopen(path, "r");
        if(f != NULL) {
            return f;
        }
        i++;
    }
    return NULL;
}

int
kinit_handle_dir_config(
        struct lassie *daemon_cfg)
{

}

int
kinit_handle_daemon_config(
        struct lassie *daemon_cfg)
{
    int res;

    struct lassie_obj *daemon_obj = lassie_to_obj(daemon_cfg);
    if(daemon_obj == NULL) {
        fprintf(stderr, "kinit: daemon config must be an object!\n");
        return -EINVAL;
    }

    struct kinit_daemon *daemon = kinit_create_daemon();
    if(daemon == NULL) {
        return -ENOMEM;
    }

    { // See if the daemon config includes a name...
        struct lassie_string *name_string;
        name_string = lassie_obj_field_string(daemon_obj, "name");
        if(name_string != NULL) {
            const char *str = lassie_string_get_value(name_string);
            if(str != NULL) {
                kinit_daemon_set_name(daemon, str);
            }
        }
    }

    do { 
        struct lassie_array *exec_array;
        exec_array = lassie_obj_field_array(daemon_obj, "exec");
        if(exec_array == NULL) {
            break;
        }

        unsigned long len = lassie_array_length(exec_array);
        const char **entries = malloc(sizeof(const char *) * len+1);
        memset(entries, 0, sizeof(const char *) * len+1);

        unsigned long i = 0;
        struct lassie *iter = lassie_array_begin(exec_array);
        while(iter) {
            struct lassie_string *str = lassie_to_string(iter);
            if(str == NULL) {
                fprintf(stderr, "kinit: daemon config \"exec\" array must only contain strings!\n");
                return -EINVAL;
            }
            const char *value = lassie_string_get_value(str);
            entries[i] = value;

            i++;
            iter = lassie_array_next(exec_array, iter);
        }

        kinit_daemon_set_exec_command(daemon, entries, len);

    } while(0);

    return 0;
}

int
kinit_handle_config(
        struct lassie *cfg)
{
    int res;

    struct lassie_obj *cfg_obj = lassie_to_obj(cfg);
    if(cfg_obj == NULL) {
        fprintf(stderr, "kinit: Config must be an object!\n");
        return -EINVAL;
    }

    struct lassie *daemon = lassie_obj_get(cfg_obj, "daemon");
    if(daemon == NULL) {
        fprintf(stderr, "kinit: WARNING config missing \"daemon\" field!\n");
    } else {
        struct lassie_array *daemon_array = lassie_to_array(daemon);
        if(daemon_array == NULL) {
            fprintf(stderr, "kinit: ERROR \"daemon\" field in config is not an array!\n");
            return -EINVAL;
        }
        struct lassie *daemon = lassie_array_begin(daemon_array);
        while(daemon) {
            res = kinit_handle_daemon_config(daemon);
            if(res) {
                return res;
            }
            daemon = lassie_array_next(daemon_array, daemon);
        }
    }

    return 0;
}

int
kinit_read_config(void)
{
    int res;

    FILE *cfg_file = kinit_open_root_config();
    if(cfg_file == NULL) {
        fprintf(stderr, "kinit: Failed to find config file!\n");
        return -ENXIO;
    }

    struct lassie *cfg = lassie_json_read(cfg_file);
    fclose(cfg_file);
    if(cfg == NULL) {
        fprintf(stderr, "kinit: Failed to read json config file!\n");
        return -EINVAL;
    }

    printf("kinit: Config...\n");
    res = lassie_json_write(stdout, cfg, 0, 0);
    if(res) {
        return res;
    }
    putc('\n', stdout);

    res = kinit_handle_config(cfg);
    lassie_destroy(cfg);
    if(res) {
        fprintf(stderr, "kinit: failed to handle root config!\n");
        return res;
    }

    return 0;
}

