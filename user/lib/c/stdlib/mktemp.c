
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static inline char
inc_fpf_char(char c)
{
    if(('a' <= c && c < 'z') || ('A' <= c && c < 'Z') || ('0' <= c && c < '9'))
    {
        return c + 1;
    }

    if(c == 'z')
    {
        return 'A';
    }
    else if(c == 'Z')
    {
        return '0';
    }
    else
    {
        return 'a';
    }
}

int
do_mktemp(char *template, char *buffer, size_t buflen, int *fd_out)
{

    size_t template_size = strlen(template);

    if(buflen != template_size + 1)
    {
        return -EFAULT;
    }

    strncpy(buffer, template, buflen);
    buffer[buflen - 1] = '\0';

    char *iter = buffer;
    while(*iter)
    {
        if(*iter == 'X')
        {
            *iter = '0';
        }
        iter++;
    }

    // Increment the buffer
    while(1)
    {

        int fd = open(buffer, O_RDWR | O_CREAT | O_EXCL);
        if(fd != -1)
        {
            if(fd_out != NULL)
            {
                *fd_out = fd;
            }
            else
            {
                close(fd);
            }
            return 0;
        }

        for(size_t ci = template_size; ci >= 0; ci--)
        {

            if(ci == 0)
            {
                // Made it through all possible file names
                return -ENOMEM;
            }

            size_t i = ci - 1;

            if(template[i] == 'X')
            {
                buffer[i] = inc_fpf_char(buffer[i]);
                if(buffer[i] != '0')
                {
                    break;
                }
            }
        }
    }
}

char *
mktemp(char *buffer_str)
{
    int res;
    size_t buflen = strlen(buffer_str) + 1;
    char saved_copy[buflen + 1];
    strncpy(saved_copy, buffer_str, buflen);
    saved_copy[buflen - 1] = '\0';

    res = do_mktemp(saved_copy, buffer_str, buflen, NULL);
    if(res)
    {
        return NULL;
    }

    return buffer_str;
}

int
mkstemp(char *template)
{
    int res;

    size_t template_size = strlen(template);
    char buffer[template_size + 1];

    strncpy(buffer, template, template_size);
    buffer[template_size] = '\0';

    int fd;

    res = do_mktemp(template, buffer, template_size + 1, &fd);
    if(res)
    {
        errno = res;
        return -1;
    }

    return fd;
}
