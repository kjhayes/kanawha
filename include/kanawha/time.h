#ifndef __KANAWHA__TIME_H__
#define __KANAWHA__TIME_H__

#include <kanawha/stdint.h>

typedef size_t cycles_t;

typedef size_t freq_t;
typedef size_t hz_t;
typedef size_t khz_t;
typedef size_t mhz_t;
typedef size_t ghz_t;

#define HZ_PER_KHZ 1000
#define HZ_PER_MHZ 1000000
#define HZ_PER_GHZ 1000000000

static inline freq_t
hz_to_freq(hz_t hz) {
    return hz;
}

static inline freq_t
khz_to_freq(khz_t khz) {
    return khz * HZ_PER_KHZ;
}

static inline freq_t
mhz_to_freq(mhz_t mhz) {
    return mhz * HZ_PER_MHZ;
}

static inline freq_t
ghz_to_freq(mhz_t mhz) {
    return mhz * HZ_PER_GHZ;
}

static inline hz_t
freq_to_hz(freq_t freq) {
    return freq;
}

static inline khz_t
freq_to_khz(freq_t freq) {
    return freq / HZ_PER_KHZ;
}

static inline mhz_t
freq_to_mhz(freq_t freq) {
    return freq / HZ_PER_MHZ;
}

static inline ghz_t
freq_to_ghz(freq_t freq) {
    return freq / HZ_PER_GHZ;
}

// For now, duration_t is always measure in nano-seconds,
// but we want the API to keep this flexible in the future
typedef size_t time_t;
typedef time_t duration_t;

typedef size_t sec_t;
typedef size_t msec_t;
typedef size_t nsec_t;

#define NSEC_PER_SEC 1000000000
#define NSEC_PER_MSEC 1000000

static inline sec_t
duration_to_sec(duration_t time) {
    return time / NSEC_PER_SEC;
}

static inline msec_t
duration_to_msec(duration_t time) {
    return time / NSEC_PER_MSEC;
}

static inline nsec_t
duration_to_nsec(duration_t time) {
    return time;
}

static inline duration_t
sec_to_duration(sec_t sec) {
    return sec * NSEC_PER_SEC;
}

static inline duration_t
msec_to_duration(msec_t msec) {
    return msec * NSEC_PER_MSEC;
}

static inline duration_t
nsec_to_duration(nsec_t nsec) {
    return nsec;
}

static inline duration_t
freq_cycles_to_duration(freq_t freq, cycles_t cycles)
{

    // hz [ 1 / sec ]
    // cycles [ 1 ]
    // duration [ ns ]
    //
    // duration = (cycles / hz) * NSEC_PER_SEC
    //          = (cycles * NSEC_PER_SEC) / hz (Otherwise we'd only get second level precision not nano-second)

    return nsec_to_duration((nsec_t)((cycles * NSEC_PER_SEC) / freq_to_hz(freq)));
}

static inline cycles_t
cycles_from_duration(duration_t duration, freq_t freq)
{
    // hz [ 1 / sec ]
    // cycles [ 1 ]
    // duration [ ns ]
    //
    // cycles = (duration / NSEC_PER_SEC) * hz
    //        = (duration * hz) / NSEC_PER_SEC (Otherwise we'd only get second level precision not nano-second)
    return (duration_to_nsec(duration) * freq_to_hz(freq)) / NSEC_PER_SEC;
}

static inline freq_t
timed_cycles_to_freq(duration_t elapsed_time, cycles_t elapsed_cycles)
{
    hz_t hz = ((elapsed_cycles * NSEC_PER_SEC) / duration_to_nsec(elapsed_time));
    return hz_to_freq(hz);
}

#endif
