#ifndef __LENSD__DISPLAY_H__
#define __LENSD__DISPLAY_H__

#include <elk/list.h>

struct display;

int display_init(void);
int display_deinit(void);

int add_display(const char *path, int mode);
int add_all_displays(const char *dir_path);

int foreach_display(
        int(*callback)(struct display *disp, void *state),
        void *state);

int display_flush_all(void);
int displays_lock(void);
int displays_unlock(void);
struct display *display_get_primary(void);

#endif
