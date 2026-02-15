#ifndef __ELK_DL__DLFCN_H__
#define __ELK_DL__DLFCN_H__

#define RTLD_LAZY   (1)
#define RTLD_NOW    (2)
#define RTLD_GLOBAL (3)
#define RTLD_LOCAL  (4)

void  *dlopen(const char *, int);
void  *dlsym(void *, const char *);
int    dlclose(void *);
char  *dlerror(void);

#endif
