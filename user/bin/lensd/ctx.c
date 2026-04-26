
#include "lensd.h"
#include <ilist.h>
#include <semaphore.h>
#include <stdlib.h>
#include <errno.h>

static ilist_t ctx_list;
static sem_t ctx_list_lock;

static struct lens_client_ctx *
create_lens_client_ctx(
        struct lens_client *client)
{
    int res;

    struct lens_client_ctx *ctx;
    ctx = malloc(sizeof(*ctx));
    if(ctx == NULL) {
        return NULL;
    }

    ctx->percent_pos_x  = 0.1;
    ctx->percent_pos_y  = 0.1;
    ctx->percent_width  = 0.8;
    ctx->percent_height = 0.8;
    ctx->resized = 1;
    ctx->moved = 1;

    ctx->client = client;
    res = render_init_ctx(ctx);
    if(res) {
        fprintf(stderr, "lensd: failed to initialize render state of window context!\n");
        free(ctx);
        return NULL;
    }

    return ctx;
}

static int
destroy_lens_client_ctx(
        struct lens_client_ctx *ctx)
{
    render_deinit_ctx(ctx);
    lens_server_close_client(ctx->client);
    free(ctx);
    return 0;
}

int
ctx_init(void)
{
    int res;
    ilist_init(&ctx_list);
    res = sem_init(&ctx_list_lock, 1, 1);
    if(res) {
        return res;
    }
    return 0;
}

int
ctx_deinit(void)
{
    while(sem_wait(&ctx_list_lock)) {}

    ilist_node_t *iter;
    ilist_for_each(iter, &ctx_list) {
        struct lens_client_ctx *ctx =
            container_of(iter, struct lens_client_ctx, list_node);

        destroy_lens_client_ctx(ctx);
    }

    sem_post(&ctx_list_lock);
    sem_destroy(&ctx_list_lock);
    return 0;
}

int add_lens_client(struct lens_client *client)
{
    struct lens_client_ctx *ctx =
        create_lens_client_ctx(client);
    if(ctx == NULL) {
        return -ENOMEM;
    }
    while(sem_wait(&ctx_list_lock)) {}
    ilist_push_head(&ctx_list, &ctx->list_node);
    sem_post(&ctx_list_lock);
    return 0;
}
int remove_lens_client(struct lens_client_ctx *ctx)
{
    while(sem_wait(&ctx_list_lock)) {}
    ilist_remove(&ctx_list, &ctx->list_node);
    sem_post(&ctx_list_lock);
    destroy_lens_client_ctx(ctx);
    return 0;
}

int foreach_lens_client(
        int(*callback)(struct lens_client_ctx *ctx, void *state),
        void *state)
{
    int res;
    while(sem_wait(&ctx_list_lock)) {}

    size_t num_clients = ilist_count(&ctx_list);
    for(size_t i = 0; i < num_clients; i++) {
        ilist_node_t *head;
        head = ilist_pop_head(&ctx_list);

        if(head == NULL) {
            break;
        }

        struct lens_client_ctx *ctx =
            container_of(head, struct lens_client_ctx, list_node);

        (*callback)(ctx, state);

        ilist_push_tail(&ctx_list, &ctx->list_node);
    }

    sem_post(&ctx_list_lock);
    return 0;
}

int foreach_lens_client_back_to_front(
        int(*callback)(struct lens_client_ctx *ctx, void *state),
        void *state)
{
    int res;
    while(sem_wait(&ctx_list_lock)) {}

    size_t num_clients = ilist_count(&ctx_list);
    for(size_t i = 0; i < num_clients; i++) {
        ilist_node_t *head;
        head = ilist_pop_tail(&ctx_list);

        if(head == NULL) {
            break;
        }

        struct lens_client_ctx *ctx =
            container_of(head, struct lens_client_ctx, list_node);

        (*callback)(ctx, state);

        ilist_push_head(&ctx_list, &ctx->list_node);
    }

    sem_post(&ctx_list_lock);
    return 0;
}

int ctx_order_cycle(void)
{
    int res;
    while(sem_wait(&ctx_list_lock)) {}

    size_t num_ctx = ilist_count(&ctx_list);
    printf("cycling %lu contextes\n", num_ctx);

    ilist_node_t *node = ilist_pop_tail(&ctx_list);
    if(node != NULL) {
        ilist_push_head(&ctx_list, node);
    }

    sem_post(&ctx_list_lock);
    render_mark_full_redraw();
    return 0;
}

static int
poll_client_callback(
        struct lens_client_ctx *ctx,
        void *state)
{
    return lens_server_poll_client(ctx->client);
}

int
ctx_loop_iter(void)
{
    foreach_lens_client(poll_client_callback, NULL);
}

int ctx_lock_order(void)
{
    while(sem_wait(&ctx_list_lock)) {}
}
int ctx_unlock_order(void)
{
    sem_post(&ctx_list_lock);
}

struct lens_client_ctx *
ctx_get_active(void)
{
    ilist_node_t *iter = ilist_peek_head(&ctx_list);
    if(iter == NULL) {
        return NULL;
    }
    return container_of(
            iter,
            struct lens_client_ctx,
            list_node);
}

