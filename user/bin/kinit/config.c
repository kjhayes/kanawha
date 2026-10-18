
#include "config.h"
#include "daemon.h"
#include "path.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <lassie/json.h>
#include <kanawha/syscall.h>
#include <kanawha/mount.h>
#include <kanawha/environ.h>

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

static int
kinit_handle_env_config(
        struct lassie *env)
{
    int res;

    struct lassie_obj *obj = lassie_to_obj(env);
    if(obj == NULL) {
            fprintf(stderr, "kinit_handle_env_config: \"env\" field must be an object!\n");
        return -EINVAL;
    }
    struct lassie_field *iter = lassie_obj_fields_begin(obj);
    while(iter) {
        const char *key = lassie_field_key(iter);
        struct lassie *g_value = lassie_field_value(iter);
        if(key == NULL || g_value == NULL) {
            return -EINVAL;
        }
        struct lassie_string *vstr = lassie_to_string(g_value);
        if(vstr == NULL) {
            fprintf(stderr, "kinit_handle_env_config: \"env\" values must be strings!\n");
            return -EINVAL;
        }
        const char *value = lassie_string_get_value(vstr);
        if(value == NULL) {
            value = "";
        }

        res = kanawha_sys_environ(
                key,
                (char*)value,
                strlen(value),
                ENV_SET);
        if(res) {
            fprintf(stderr, "kinit_handle_env_config: WARNING failed to set \"%s\"=\"%s\"!\n",
                    key,
                    value);
        }
        
        iter = lassie_obj_fields_next(obj, iter);
    }
    return 0;
}

static struct kinit_path *
kinit_handle_mount_path_config(
        struct lassie_obj *mnt_obj,
        const char *name)
{
    const char *source = NULL;
    const char *fs_type = NULL;
    unsigned long mount_flags = 0;

    do {
        struct lassie_string *lstr;
        lstr = lassie_obj_field_string(mnt_obj, "source");
        if(lstr == NULL) {
            // Default to empty string...
            source = "";
            break;
        }
        source = lassie_string_get_value(lstr);
    } while(0);

    do {
        struct lassie_string *lstr;
        lstr = lassie_obj_field_string(mnt_obj, "fs");
        if(lstr == NULL) {
            fprintf(stderr, "kinit_handle_mount_path_config: missing \"fs\" field!\n");
            return NULL;
        }
        fs_type = lassie_string_get_value(lstr);
    } while(0);

    do {
        struct lassie_boolean *special = lassie_obj_field_boolean(mnt_obj, "special");
        if(special && lassie_boolean_get_value(special)) {
            mount_flags |= MOUNT_SPECIAL;
        } else {
            mount_flags |= MOUNT_FILE;
        }
    } while(0);

    struct kinit_path *path;
    path = kinit_create_mountpoint(
            name,
            source,
            fs_type,
            mount_flags);
    if(path == NULL) {
        fprintf(stderr, "kinit_handle_mount_path_config: failed to create mountpoint kinit_path!\n");
        return NULL;
    }

    return path;
}

static struct kinit_path *
kinit_handle_dir_path_config(
        struct lassie_obj *dir_obj,
        const char *name)
{
    struct kinit_path *path = NULL;
    path = kinit_create_dir(name);
    if(path == NULL) {
        return NULL;
    }
    return path;
}

static struct kinit_path *
kinit_handle_path_config(
        struct lassie *generic_path)
{
    int res;

    struct lassie_obj *path_obj = lassie_to_obj(generic_path);
    if(path_obj == NULL) {
        return NULL;
    }

    unsigned int is_mount = 1;
    {
        // Check for a "mount" : BOOL field
        struct lassie *mount = lassie_obj_get(path_obj, "mount");
        if(mount != NULL) {
            struct lassie_boolean *mount_bool = lassie_to_boolean(mount);
            if(mount_bool == NULL) {
                fprintf(stderr, "kinit_handle_path_config: path has \"mount\" field but it is not a booelan!\n");
                return NULL;
            }
            is_mount = lassie_boolean_get_value(mount_bool);
        }
    }

    const char *name = "root";
    {
        struct lassie_string *name_str = lassie_obj_field_string(path_obj, "name");
        if(name_str != NULL) {
            name = lassie_string_get_value(name_str);
        }
    }

    struct kinit_path *path = NULL;
    if(is_mount) {
        path = kinit_handle_mount_path_config(path_obj, name);
    } else {
        path = kinit_handle_dir_path_config(path_obj, name);
    }
    if(path == NULL) {
        return NULL;
    }

    do {
        struct lassie_array *subdirs = lassie_obj_field_array(path_obj, "subdir");
        if(subdirs == NULL) {
            break;
        }
        struct lassie *subdir = lassie_array_begin(subdirs);
        while(subdir) {
            struct kinit_path *subdir_path = kinit_handle_path_config(subdir);
            if(subdir_path == NULL) {
                fprintf(stderr, "kinit_handle_path_config: Failed to parse subdirectory object! (Ignoring)\n");
            } else {
                res = kinit_path_append_child(path, subdir_path);
                if(res) {
                    fprintf(stderr, "kinit_handle_path_config: Failed to append subdir path! (Ignoring)\n");
                }
            }
            subdir = lassie_array_next(subdirs, subdir);
        }
    } while(0);

    return path;
}

static int
kinit_handle_root_config(
        struct lassie *root_cfg)
{
    int res;
    struct kinit_path *path = kinit_handle_path_config(root_cfg);
    if(path == NULL) {
        return -EINVAL;
    }
    res = kinit_path_set_root(path);
    if(res) {
        return res;
    }
    return 0;
}

static int
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

    struct lassie *root = lassie_obj_get(cfg_obj, "root");
    if(root == NULL) {
        fprintf(stderr, "kinit: WARNING config missing \"root\" field!\n");
    } else {
        res = kinit_handle_root_config(root);
        if(res) {
            return res;
        }
    }

    struct lassie *env = lassie_obj_get(cfg_obj, "env");
    if(root != NULL) {
        res = kinit_handle_env_config(env);
        if(res) {
            return res;
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

