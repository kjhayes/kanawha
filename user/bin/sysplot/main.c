
#include <windd/windd.h>
#include <kfb/kfb.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <kanawha/time.h>
#include <threads.h>
#include <kanawha/sys-wrappers.h>

static int
window_poll_main(void *_win) {
    struct window *win = _win;
    while(!windd_window_disconnected(win)) {
        windd_window_poll(win);
    }
    return 0;
}

struct metric {
    size_t max;
    size_t min;
    size_t cur;
    const char *name;
    kfb_rgba_t color;
    void(*update)(struct metric *self);
};

static int metrics_lock = 0;
static inline void lock_metrics(void) {while(__atomic_fetch_or(&metrics_lock, 1, __ATOMIC_SEQ_CST)) {}}
static inline void unlock_metrics(void) {__atomic_fetch_and(&metrics_lock, 0, __ATOMIC_SEQ_CST);}

static int metrics_buflen = 0;
static int num_metrics = 0;
static struct metric **metrics = NULL;

static inline void
register_metric(
        struct metric *metric)
{
    lock_metrics();
    if(num_metrics == metrics_buflen) {
        metrics_buflen++;
        struct metric **n_metrics = malloc(sizeof(struct metric *) * (metrics_buflen));
        if(metrics != NULL) {
            memcpy(n_metrics, metrics, sizeof(struct metric*) * num_metrics);
        }
        metrics = n_metrics;
        if(metrics == NULL) {
            abort();
        }
    }
    metrics[num_metrics] = metric;
    num_metrics++;
    unlock_metrics();
}

static int
render_main(void *_win) {
    struct window *window = _win;

    int running = 1;

    while(running)
    {
        sleep(1);

        struct gfx_layout layout;
        windd_window_get_layout(window, &layout);
        windd_window_reload_buffer(window);
        windd_window_lock_buffer(window);

        if(!window->layout_valid || !(window->buffer_size > 0)) {
            windd_window_unlock_buffer(window);
            continue;
        }

        // Draw
        size_t bar_width = window->layout.width / num_metrics;

        uint32_t bg = 0xFF101010;
        struct kfb_image bg_img = {
            .data = (void*)&bg,
            .resx = 1,
            .resy = 1,
            .order = GFX_ORDER_ROW_MAJOR,
            .format = GFX_FORMAT_RGBA32,
            .offset = 0,
            .stride = 4,
            .data_size = 4,
        };

        lock_metrics();
        for(size_t mi = 0; mi < num_metrics; mi++) {  
            struct metric *m = metrics[mi];
            //printf("update(%s)\n", m->name);
            (*m->update)(m);
        }
        for(size_t mi = 0; mi < num_metrics; mi++) {
            struct metric *m = metrics[mi];
            struct kfb_image img = {
                .data = (void*)&m->color,
                .resx = 1,
                .resy = 1,
                .order = GFX_ORDER_ROW_MAJOR,
                .format = GFX_FORMAT_RGBA32,
                .offset = 0,
                .stride = 4,
                .data_size = 4,
            };

            double range = (double)m->max - (double)m->min;
            double offset = (double)m->cur - (double)m->min;
            double percentage = offset / range;

            size_t height = percentage * layout.height;
            if(height > layout.height) {
                height = layout.height;
            }
            
            size_t y_off = layout.height - height;

            kfb_blit_image(
                    window->buffer,
                    bar_width,
                    height,
                    bar_width * mi,
                    y_off,
                    &layout,
                    &img);
            kfb_blit_image(
                window->buffer,
                bar_width,
                layout.height - height,
                bar_width * mi,
                0,
                &layout,
                &bg_img);

        }
        unlock_metrics();

        windd_window_unlock_buffer(window);
    }
}

static size_t read_file_to_number(const char *path)
{
    FILE *file = fopen(path, "r");
    if(file == NULL) {
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
init_mem_metric(void) {
    static struct metric m = {
        .min = 0,
        .max = 1,
        .cur = 0,
        .name = "memory",
        .update = mem_update,
        .color = {
            .r = 0x00,
            .g = 0x80,
            .b = 0x00,
            .a = 0xFF,
        },
    };
    register_metric(&m);
}

struct cpu_metric {
    const char *name;
    struct metric metric;
};

static void
cpu_update(struct metric *metric)
{
    //printf("cpu_update()\n");
    struct cpu_metric *m = ((void*)metric) - offsetof(struct cpu_metric, metric);
    char pathbuf[128];
    snprintf(pathbuf, 128, "/sys/cpu/%s/idle", m->name);
    pathbuf[127] = '\0';
    //printf("reading file %s\n", pathbuf);

    size_t idle_percent = read_file_to_number(pathbuf);
    metric->cur = 100 - idle_percent;
}

static void
init_cpu_metric(const char *name) {
    struct cpu_metric *cpu = malloc(sizeof(struct cpu_metric));
    cpu->name = name;
    cpu->metric = (struct metric){
        .min = 0,
        .max = 100,
        .cur = 0,
        .name = "cpu",
        .update = cpu_update,
        .color = {
            .r = 0x80,
            .g = 0x00,
            .b = 0x00,
            .a = 0xFF,
        },
    };
    register_metric(&cpu->metric);
}

int main(int argc, const char **argv)
{
    int res;
    res = windd_client_init();
    if(res) {
        fprintf(stderr, "Failed to initialize windd!\n");
        exit(EXIT_FAILURE);
    }
    struct window *window = windd_client_open();
    if(window == NULL) {
        fprintf(stderr, "Failed to open window!\n");
        exit(EXIT_FAILURE);
    }

    thrd_t window_renderer;
    thrd_create(&window_renderer, render_main, window);

    // Register all of our metrics
    init_mem_metric();
    init_cpu_metric("apic0");
    init_cpu_metric("apic1");
    init_cpu_metric("apic2");
    init_cpu_metric("apic3");
    init_cpu_metric("apic4");
    init_cpu_metric("apic5");
    init_cpu_metric("apic6");
    init_cpu_metric("apic7");

    window_poll_main(window);

    windd_client_close(window);
    windd_client_deinit();
    return 0;
}

