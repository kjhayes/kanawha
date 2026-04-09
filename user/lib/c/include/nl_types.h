#ifndef __ELK_POSIX__NL_TYPES_H__
#define __ELK_POSIX__NL_TYPES_H__

typedef unsigned int nl_catd;
typedef unsigned int nl_item;

#define NL_SETD (0)
#define NL_CAT_LOCALE (1)

int       catclose(nl_catd);
char     *catgets(nl_catd, int, int, const char *);
nl_catd   catopen(const char *, int);

#endif
