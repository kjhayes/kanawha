#ifndef __INIT_DIR_H__
#define __INIT_DIR_H__

int
for_each_file_under(const char *dir_path,
                    void (*callback)(int dir, const char *name, void *priv),
                    void *priv);

#endif
