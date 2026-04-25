
#include <kanawha/sys-wrappers.h>
#include <kanawha/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <unistd.h>

#include <paint/paint.h>

#include <lens/lens.h>
#include <lens/gfx.h>
#include <lens/window.h>

struct metric
{
    size_t max;
    size_t min;
    size_t cur;
    const char *name;
    uint32_t color;
    void (*update)(struct metric *self);
};

static int metrics_lock = 0;
static inline void
lock_metrics(void)
{
    while(__atomic_fetch_or(&metrics_lock, 1, __ATOMIC_SEQ_CST))
    {
    }
}
static inline void
unlock_metrics(void)
{
    __atomic_fetch_and(&metrics_lock, 0, __ATOMIC_SEQ_CST);
}

static int metrics_buflen = 0;
static int num_metrics = 0;
static struct metric **metrics = NULL;

static inline void
register_metric(struct metric *metric)
{
    lock_metrics();
    if(num_metrics == metrics_buflen)
    {
        metrics_buflen++;
        struct metric **n_metrics =
            malloc(sizeof(struct metric *) * (metrics_buflen));
        if(metrics != NULL)
        {
            memcpy(n_metrics, metrics, sizeof(struct metric *) * num_metrics);
        }
        metrics = n_metrics;
        if(metrics == NULL)
        {
            abort();
        }
    }
    metrics[num_metrics] = metric;
    num_metrics++;
    unlock_metrics();
}

static int
render_metrics(struct lens_window *window)
{
    lens_window_lock_gfx(window);
    struct lens_gfx_info *info = lens_window_get_gfx_info(window);
    void *frame = lens_window_get_gfx_frame(window);

    for(int i = 0; i < info->num_layers; i++) {
        // Draw
        struct gfx_layout *layout = &info->layer_layout[i];

        size_t bar_width = layout->width / num_metrics;

        uint32_t bg_color = 0xFF101010;
        struct gfx_layout color_layout = {
            .order = GFX_ORDER_ROW_MAJOR,
            .width = 1,
            .height = 1,
            .format = GFX_FORMAT_RGBA32,
            .offset = 0,
            .stride = 4,
        };

        for(size_t mi = 0; mi < num_metrics; mi++)
        {
            struct metric *m = metrics[mi];
            (*m->update)(m);
        }
        for(size_t mi = 0; mi < num_metrics; mi++)
        {
            struct metric *m = metrics[mi];

            double range = (double)m->max - (double)m->min;
            double offset = (double)m->cur - (double)m->min;
            double percentage = offset / range;

            size_t height = percentage * layout->height;
            if(height > layout->height)
            {
                height = layout->height;
            }

            size_t y_off = layout->height - height;

            paint_blit(
                    frame,
                    info->frame_size,
                    bar_width,
                    height,
                    bar_width * mi,
                    y_off,
                    layout,
                    &m->color,
                    sizeof(m->color),
                    1, 1,
                    0, 0,
                    &color_layout);
            paint_blit(
                    frame,
                    info->frame_size,
                    bar_width,
                    layout->height - height,
                    bar_width * mi,
                    0,
                    layout,
                    &bg_color,
                    sizeof(bg_color),
                    1, 1,
                    0, 0,
                    &color_layout
                    );
        }
    }
    lens_window_unlock_gfx(window);
    return 0;
}

static size_t
read_file_to_number(const char *path)
{
    FILE *file = fopen(path, "r");
    if(file == NULL)
    {
        fprintf(stderr, "failed to open file: \"%s\"\n", path);
        return 0;
    }
    static char buffer[128];
    size_t amt_read = fread(buffer, 1, 127, file);
    buffer[amt_read] = '\0';
    size_t v = strtoul(buffer, NULL, 0);
    fclose(file);
    return v;
}

static void
mem_update(struct metric *metric)
{
    size_t total = read_file_to_number("/sys/info/mem_total");
    size_t free = read_file_to_number("/sys/info/mem_free");
    size_t allocated = total - free;
    metric->max = total;
    metric->cur = allocated;
}

static void
init_mem_metric(void)
{
    static struct metric m = {
        .min = 0,
        .max = 1,
        .cur = 0,
        .name = "memory",
        .update = mem_update,
        .color = 0xFF008000,
    };
    register_metric(&m);
}

struct cpu_metric
{
    const char *name;
    struct metric metric;
};

static void
cpu_update(struct metric *metric)
{
    // printf("cpu_update()\n");
    struct cpu_metric *m =
        ((void *)metric) - offsetof(struct cpu_metric, metric);
    char pathbuf[128];
    snprintf(pathbuf, 128, "/sys/cpu/%s/idle", m->name);
    pathbuf[127] = '\0';
    // printf("reading file %s\n", pathbuf);

    size_t idle_percent = read_file_to_number(pathbuf);
    metric->cur = 100 - idle_percent;
}

static void
init_cpu_metric(const char *name)
{
    struct cpu_metric *cpu = malloc(sizeof(struct cpu_metric));
    cpu->name = strdup(name);
    cpu->metric = (struct metric){
        .min = 0,
        .max = 100,
        .cur = 0,
        .name = "cpu",
        .update = cpu_update,
        .color = 0xFF000080,
    };
    register_metric(&cpu->metric);
}

int
main(int argc, const char **argv)
{
    int res;

    res = lens_init();
    if(res) {
        fprintf(stderr, "Failed to initialize windowing library!\n");
        exit(EXIT_FAILURE);

    }

    struct lens_window *window = lens_open_window();
    if(window == NULL)
    {
        fprintf(stderr, "Failed to open window!\n");
        exit(EXIT_FAILURE);
    }

    // Register all of our metrics
    init_mem_metric();

    { // init all of our metrics
        int dir;
        res = kanawha_sys_open("/sys/cpu", FILE_PERM_READ, 0, &dir);
        if(res)
        {
            perror("failed to open \"/sys/cpu\"\n");
            exit(EXIT_FAILURE);
        }

        res = kanawha_sys_dirbegin(dir);
        while(res == 0)
        {
            char cpu_name[128];
            kanawha_sys_dirname(dir, cpu_name, 128);
            cpu_name[127] = '\0';
            printf("found cpu \"%s\"\n", cpu_name);
            init_cpu_metric(cpu_name);
            res = kanawha_sys_dirnext(dir);
        }

        kanawha_sys_close(dir);
    }

    int running = 1;
    while(running) {
        lens_window_poll(window);
        render_metrics(window);
        lens_window_flush(window);
        sleep(1);
    }

    lens_close_window(window);
    lens_deinit();
    return 0;
}
