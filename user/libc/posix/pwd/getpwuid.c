
#include <pwd.h>
#include <stdio.h>
#include <stddef.h>

int getpwuid_r(
        uid_t uid,
        struct passwd *passwd,
        char *buffer,
        size_t buflen,
        struct passwd **passwd_out)
{
    passwd->pw_dir = "/home/";
    passwd->pw_gid = 0;
    passwd->pw_uid = 0;
    passwd->pw_passwd = "HASHED-PW";
    passwd->pw_name = "usr";
    passwd->pw_gecos = "usr";
    passwd->pw_shell = "sh";

    if(passwd_out) {
        *passwd_out = passwd;
    }

    return 0;
}

struct passwd *getpwuid(uid_t uid)
{
#define GETPWUID_BUFLEN 256
    static char getpwuid_buffer[GETPWUID_BUFLEN];
    static struct passwd getpwuid_passwd;

    int res;
    struct passwd *ptr;
    res = getpwuid_r(
            uid,
            &getpwuid_passwd,
            getpwuid_buffer,
            GETPWUID_BUFLEN,
            &ptr);
    if(res == -1) {
        return NULL;
    }

    return ptr;

#undef GETPWUID_BUFLEN
}

