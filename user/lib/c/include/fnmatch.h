#ifndef __ELK_POSIX__FNMATCH_H__
#define __ELK_POSIX__FNMATCH_H__

#define NM_NOMATCH   (1ULL<<0)
#define FNM_PATHNAME (1ULL<<1)
#define FNM_PERIOD   (1ULL<<2)
#define FNM_NOESCAPE (1ULL<<3)
#define FNM_NOSYS    (1ULL<<4)

int fnmatch(const char *, const char *, int);

#endif
