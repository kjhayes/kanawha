#ifndef __ELK_LIBC__FENV_H__
#define __ELK_LIBC__FENV_H__

typedef struct {

} fenv_t;

typedef struct {

} fexcept_t;

extern const fenv_t __elk_libc__default_fenv;
#define FE_DFL_ENV (&__elk_libc__default_fenv)

int  feclearexcept(int);
int  fegetenv(fenv_t *);
int  fegetexceptflag(fexcept_t *, int);
int  fegetround(void);
int  feholdexcept(fenv_t *);
int  feraiseexcept(int);
int  fesetenv(const fenv_t *);
int  fesetexceptflag(const fexcept_t *, int);
int  fesetround(int);
int  fetestexcept(int);
int  feupdateenv(const fenv_t *);

#endif
