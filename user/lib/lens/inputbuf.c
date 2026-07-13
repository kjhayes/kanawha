
#include <kanawha/input.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

struct lens_input_buffer
{
    sem_t lock;
    size_t head;
    size_t tail;

    sem_t num_evts;

    size_t buflen;
    struct input_event buffer[];
};


struct lens_input_buffer *
lens_create_input_buffer(
        size_t length)
{
    int res;

    size_t len = sizeof(struct lens_input_buffer)
              + (length * sizeof(struct input_event));
    struct lens_input_buffer *buffer = malloc(len);
    if(buffer == NULL) {
        return NULL;
    }

    buffer->head = 0;
    buffer->tail = 0;
    buffer->buflen = length;
    memset(buffer->buffer, 0, sizeof(struct input_event) * length);

    res = sem_init(&buffer->lock, 1, 1);
    if(res) {
        free(buffer);
        return NULL;
    }
    res = sem_init(&buffer->num_evts, 1, 0);
    if(res) {
        sem_destroy(&buffer->lock);
        free(buffer);
        return NULL;
    }

    return buffer;
}

int
lens_destroy_input_buffer(
        struct lens_input_buffer *buffer)
{
    sem_destroy(&buffer->lock);
    free(buffer);
    return 0;
}

int
lens_input_buffer_push(
        struct lens_input_buffer *buffer,
        struct input_event *evt)
{
    //printf("PID(%d) lens_input_buffer_push!\n", getpid());
    while(sem_wait(&buffer->lock)) {}

    if(((buffer->head+1)%buffer->buflen) == buffer->tail) {
        // The buffer is full, drop the tail event
        buffer->tail++;
        if(buffer->tail >= buffer->buflen) {
            buffer->tail = 0;
        }
    } else {
        sem_post(&buffer->num_evts);
    }

    buffer->buffer[buffer->head] = *evt;
    buffer->head++;
    if(buffer->head >= buffer->buflen) {
        buffer->head = 0;
    }

    sem_post(&buffer->lock);
    return 0;
}

int
lens_input_buffer_pop(
        struct lens_input_buffer *buffer,
        struct input_event *evt)
{
    int res;

    // Wait for an event to show up,
    // after returning from this we should have
    // effectively claimed an event.
    //printf("PID(%d) lens_input_buffer: waiting for event!\n", getpid());
    while(sem_wait(&buffer->num_evts)) {
        //printf("PID(%d) lens_input_buffer: waiting for event! (loop)\n", getpid());
    }
    //printf("PID(%d) lens_input_buffer: received event!\n", getpid());

    // Obtain the lock
    //printf("PID(%d) lens_input_buffer: waiting for lock!\n", getpid());
    while(sem_wait(&buffer->lock)) {
        //printf("PID(%d) lens_input_buffer: waiting for lock! (loop)\n", getpid());
    }
    //printf("PID(%d) lens_input_buffer: received lock!\n", getpid());

    if(buffer->head == buffer->tail) {
        sem_post(&buffer->lock);
        // Huh? We should have blocked until an
        // event was available
        //printf("PID(%d) lens_input_buffer: weird (no event)!\n", getpid());
        return 0;
    }

    *evt = buffer->buffer[buffer->tail];
    buffer->tail++;
    if(buffer->tail >= buffer->buflen) {
        buffer->tail = 0;
    }

    //printf("PID(%d) lens_input_buffer: releasing lock!\n", getpid());
    sem_post(&buffer->lock);
    return 1;
}

int
lens_input_buffer_peek(
        struct lens_input_buffer *buffer)
{
    int res;
    while(sem_wait(&buffer->lock)) {}

    if(buffer->head == buffer->tail) {
        sem_post(&buffer->lock);
        return 0;
    }

    sem_post(&buffer->lock);
    return 1;
}
