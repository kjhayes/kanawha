
#include <kanawha/uapi/syscall.h>
#include <kanawha/uapi/environ.h>
#include <kanawha/env.h>
#include <kanawha/process.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/assert.h>

#define USER_ENV_MAX_KEYLEN 128
#define USER_ENV_MAX_VALLEN 0x1000

static int
env_get(
        struct process *process,
        const char __user *key,
        char __user *dst,
        size_t len)
{
    int res;

    size_t keylen;
    res = process_strlen_usermem(
            process, key, USER_ENV_MAX_KEYLEN, &keylen);
    if(res) {
        return res;
    }

    dprintk("keylen=0x%lx\n", keylen);

    char *key_buf = kmalloc(keylen + 1);
    if(key_buf == NULL) {
        return -ENOMEM;
    }

    res = process_read_usermem(
            process,
            key_buf,
            (void __user *)key,
            keylen);
    if(res) {
        kfree(key_buf);
        return res;
    }

    key_buf[keylen] = '\0';

    dprintk("key=%s\n", key_buf);

    const char *value =
        environment_get_var(
                process->environ, key_buf);

    if(value == NULL) {
        kfree(key_buf);
        return -ENXIO;
    }

    dprintk("value=%s\n", value);

    size_t value_len = strlen(value);
    size_t min_len = (value_len+1) <= len ? value_len + 1 : len;

    res = process_write_usermem(
            process,
            dst,
            (void*)value,
            min_len);
    if(res) {
        environment_put_var(process->environ);
        kfree(key_buf);
        return res;
    }

    environment_put_var(process->environ);
    kfree(key_buf);
    return 0;
}

static int
env_set(
        struct process *process,
        const char __user *key,
        char __user *value)
{
    int res;

    size_t keylen;
    res = process_strlen_usermem(
            process, key, USER_ENV_MAX_KEYLEN, &keylen);
    if(res) {
        return res;
    }

    size_t vallen;
    res = process_strlen_usermem(
            process, value, USER_ENV_MAX_VALLEN, &vallen);
    if(res) {
        return res;
    }

    char *key_buf = kmalloc(keylen + 1);
    if(key_buf == NULL) {
        return -ENOMEM;
    }
    char *val_buf = kmalloc(vallen + 1);
    if(val_buf == NULL) {
        kfree(key_buf);
        return -ENOMEM;
    }

    res = process_read_usermem(
            process,
            key_buf,
            (void __user *)key,
            keylen);
    if(res) {
        kfree(key_buf);
        kfree(val_buf);
        return res;
    }

    res = process_read_usermem(
            process,
            val_buf,
            (void __user *)value,
            vallen);
    if(res) {
        kfree(key_buf);
        kfree(val_buf);
        return res;
    }

    key_buf[keylen] = '\0';
    val_buf[vallen] = '\0';

    res = environment_set(
            process->environ,
            key_buf,
            val_buf);
    if(res) {
        kfree(key_buf);
        kfree(val_buf);
        return res;
    }


    kfree(key_buf);
    kfree(val_buf);
    return 0;
}

static int
env_clear(
        struct process *process,
        const char __user *key)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(process->environ));

    size_t keylen;
    res = process_strlen_usermem(
            process, key, USER_ENV_MAX_KEYLEN, &keylen);
    if(res) {
        return res;
    }

    printk("syscall_env: ENV_CLEAR keylen=%p\n",
            keylen);

    char *buffer = kmalloc(keylen+1);
    if(buffer == NULL) {
        return -ENOMEM;
    }

    res = process_read_usermem(
            process,
            buffer,
            (void __user *)key,
            keylen);
    if(res) {
        kfree(buffer);
        return res;
    }

    buffer[keylen] = '\0';

    printk("syscall_env: ENV_CLEAR key=%s\n", buffer);

    res = environment_clear_var(
            process->environ, buffer);
    if(res) {
        kfree(buffer);
        return res;
    }

    kfree(buffer);
    return 0;
}

int
syscall_environ(
        struct process *process,
        const char __user *key,
        char __user *value,
        size_t len,
        int opcode)
{
    switch(opcode) {
        case ENV_GET:
            return env_get(process, key, value, len);
            break;
        case ENV_SET:
            return env_set(process, key, value);
            break;
        case ENV_CLEAR:
            return env_clear(process, key);
            break;
        default:
            return -EINVAL;
    }
}

